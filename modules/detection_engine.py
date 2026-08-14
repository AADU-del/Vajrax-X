import cv2
import numpy as np
import logging
import os
import time
# torch is imported lazily inside _load_model() to prevent
# PyTorch's C-extension from silently crashing on Windows MINGW builds.

logger = logging.getLogger(__name__)
     
# ─────────────────────────────────────────────────────────
# MODULE RULES — per-module detection targets & threat levels
# ───────────── ────────────────────────────────────────────
MODULE_RULES = {
    'border': {
        'targets': ['person','car','truck','motorcycle','backpack','suitcase'],
        'threat_map': {
            'person':'HIGH','car':'MEDIUM','truck':'HIGH',
            'motorcycle':'MEDIUM','backpack':'LOW','suitcase':'MEDIUM',
        },
        'alert_prefix': 'BORDER ALERT',
    },
    'disaster': {
        'targets': ['person','car','bus','truck','fire hydrant','boat'],
        'threat_map': {
            'person':'HIGH','car':'MEDIUM','bus':'MEDIUM',
            'truck':'MEDIUM','fire hydrant':'HIGH','boat':'MEDIUM',
        },
        'alert_prefix': 'DISASTER ALERT',
    },
    'railway': {
        'targets': ['person','bicycle','motorcycle','car','truck','dog','cat'],
        'threat_map': {
            'person':'HIGH','bicycle':'HIGH','motorcycle':'HIGH',
            'car':'HIGH','truck':'HIGH','dog':'MEDIUM','cat':'LOW',
        },
        'alert_prefix': 'RAILWAY ALERT',
    },
    'smart_city': {
        'targets': ['person','car','bicycle','motorcycle','bus','truck','traffic light','stop sign'],
        'threat_map': {
            'person':'LOW','car':'LOW','bicycle':'LOW','motorcycle':'LOW',
            'bus':'LOW','truck':'MEDIUM','traffic light':'LOW','stop sign':'LOW',
        },
        'alert_prefix': 'CITY MONITOR',
    },
    'mining': {
        'targets': ['person','truck','car','backpack'],
        'threat_map': {
            'person':'MEDIUM','truck':'LOW','car':'LOW','backpack':'LOW',
        },
        'alert_prefix': 'MINING ALERT',
    },
    'forest': {
        'targets': ['person','car','truck','bird','cat','dog','horse','cow','bear'],
        'threat_map': {
            'person':'HIGH','car':'MEDIUM','truck':'HIGH',
            'bird':'LOW','cat':'LOW','dog':'LOW',
            'horse':'LOW','cow':'LOW','bear':'HIGH',
        },
        'alert_prefix': 'FOREST ALERT',
    },
    'satellite': {
        'targets': [],  # All COCO classes
        'threat_map': {
            'person':'HIGH','car':'MEDIUM','truck':'MEDIUM',
            'bus':'LOW','motorcycle':'MEDIUM','bicycle':'LOW',
            'boat':'MEDIUM','airplane':'HIGH','train':'LOW',
        },
        'alert_prefix': 'SATELLITE SCAN',
    },
}

THREAT_COLORS = {
    'LOW':    (0, 200, 80),
    'MEDIUM': (0, 165, 255),
    'HIGH':   (0, 0, 255),
}

# Satellite imagery label remapping
SATELLITE_LABEL_MAP = {
    'person':        'Personnel',
    'car':           'Ground Vehicle',
    'truck':         'Heavy Vehicle',
    'bus':           'Transport Vehicle',
    'motorcycle':    'Motorcycle',
    'bicycle':       'Bicycle/Cycle',
    'boat':          'Watercraft',
    'airplane':      'Aircraft',
    'train':         'Rail Vehicle',
    'traffic light': 'Infrastructure',
    'stop sign':     'Road Sign',
    'fire hydrant':  'Ground Equipment',
    'backpack':      'Personnel (Bag)',
    'suitcase':      'Cargo',
    'umbrella':      'Cover/Canopy',
    'bird':          'Aerial Object',
    'cat':           'Animal (Small)',
    'dog':           'Animal (Medium)',
    'horse':         'Animal (Large)',
    'cow':           'Livestock',
    'sheep':         'Livestock',
    'bear':          'Large Animal (Threat)',
}


# ─────────────────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────────────────
class DetectionEngine:

    def __init__(self, model_name=None):
        self.model = None
        self.model_loaded = False
        self.load_error = None
        self.model_name = model_name
        self._load_model()

    def _load_model(self):
        """Load YOLO model — scoped torch.load patch for PyTorch 2.6+ compatibility."""
        try:
            from ultralytics import YOLO
        except ImportError:
            self.load_error = 'ultralytics not installed. Run: pip install ultralytics'
            logger.error(self.load_error)
            return
        try:
            import torch  # Lazy import — avoids Windows MINGW C-level crash at startup
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_name = self.model_name or os.environ.get('YOLO_MODEL', 'yolov8n.pt')
            model_path = os.path.join(project_root, model_name)

            # Bug #10: Scoped patch — only override weights_only for this load call,
            # restore the original torch.load immediately after. This avoids a global
            # security bypass while still supporting PyTorch 2.6+ strict defaults.
            _orig_load = torch.load
            try:
                torch.load = lambda *a, **kw: _orig_load(
                    *a, **{**kw, 'weights_only': False}
                )
                self.model = YOLO(model_path)
            finally:
                torch.load = _orig_load  # Always restore, even on error

            # Warm-up so first real call is fast
            dummy = np.zeros((480, 640, 3), dtype=np.uint8)
            self.model(dummy, verbose=False)
            self.model_loaded = True
            logger.info(f'YOLO model loaded from {model_path}')
        except Exception as e:
            self.load_error = str(e)
            logger.error(f'Model load error: {e}')

    # ── helpers ──────────────────────────────────────────

    def _get_module_config(self, module_name):
        return MODULE_RULES.get(module_name, MODULE_RULES['smart_city'])

    def _classify_threat(self, label, confidence, module_name):
        config = self._get_module_config(module_name)
        base = config['threat_map'].get(label.lower(), 'LOW')
        # Boost threat on very high confidence
        if confidence > 0.85:
            if base == 'LOW':   return 'MEDIUM'
            if base == 'MEDIUM': return 'HIGH'
        return base

    def _clamp_bbox(self, bbox, w, h):
        """Clamp bounding box to frame dimensions — prevents crash on edge detections."""
        x1 = max(0, min(int(bbox[0]), w - 1))
        y1 = max(0, min(int(bbox[1]), h - 1))
        x2 = max(0, min(int(bbox[2]), w - 1))
        y2 = max(0, min(int(bbox[3]), h - 1))
        return x1, y1, x2, y2

    # ── drawing ──────────────────────────────────────────

    def _draw_detections(self, frame, detections, module_name):
        """Draw bounding boxes + labels on a regular camera/upload frame."""
        config = self._get_module_config(module_name)
        out = frame.copy()
        fh, fw = out.shape[:2]

        # Header bar
        overlay = out.copy()
        cv2.rectangle(overlay, (0, 0), (fw, 36), (0, 0, 0), -1)
        cv2.addWeighted(overlay, 0.65, out, 0.35, 0, out)
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        cv2.putText(out, f"VAJRA-X | {config['alert_prefix']} | {ts}",
                    (5, 23), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 150), 1)

        for det in detections:
            bbox = det.get('bbox')
            if not bbox:
                continue
            x1, y1, x2, y2 = self._clamp_bbox(bbox, fw, fh)  # FIX: clamp
            if x2 <= x1 or y2 <= y1:
                continue  # Skip degenerate boxes

            threat  = det['threat_level']
            color   = THREAT_COLORS.get(threat, (0, 200, 80))
            label   = det['label']
            conf    = det['confidence']

            cv2.rectangle(out, (x1, y1), (x2, y2), color, 2)

            txt = f"{label} {conf:.0%} [{threat}]"
            (tw, th), _ = cv2.getTextSize(txt, cv2.FONT_HERSHEY_SIMPLEX, 0.44, 1)
            # Label background — keep inside frame
            ly = max(y1, th + 8)
            cv2.rectangle(out, (x1, ly - th - 6), (x1 + tw + 4, ly), color, -1)
            cv2.putText(out, txt, (x1 + 2, ly - 3),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.44, (0, 0, 0), 1)

            # Targeting corners
            cl = 12
            for px, py, dx, dy in [(x1,y1,1,1),(x2,y1,-1,1),(x1,y2,1,-1),(x2,y2,-1,-1)]:
                cv2.line(out, (px, py), (px + dx*cl, py), (255,255,255), 2)
                cv2.line(out, (px, py), (px, py + dy*cl), (255,255,255), 2)

        if detections:
            cv2.putText(out, f"Objects: {len(detections)}",
                        (fw - 120, fh - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.48, (0, 255, 150), 1)
        return out

    def _draw_satellite_detections(self, frame, detections, module_name):
        """Draw satellite-specific overlay with targeting reticle."""
        out = frame.copy()
        fh, fw = out.shape[:2]

        # Semi-transparent header
        overlay = out.copy()
        cv2.rectangle(overlay, (0, 0), (fw, 36), (0, 0, 0), -1)
        cv2.addWeighted(overlay, 0.7, out, 0.3, 0, out)
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC')
        cv2.putText(out, f"VAJRA-X SATELLITE | {module_name.upper()} | {ts}",
                    (5, 23), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 255, 150), 1)

        # Map grid overlay
        step_x, step_y = fw // 4, fh // 4
        for i in range(1, 4):
            cv2.line(out, (i*step_x, 36), (i*step_x, fh), (0, 80, 40), 1)
            cv2.line(out, (0, i*step_y), (fw, i*step_y), (0, 80, 40), 1)

        # Center crosshair
        cx, cy = fw // 2, fh // 2
        cv2.line(out, (cx-22, cy), (cx+22, cy), (0, 255, 180), 1)
        cv2.line(out, (cx, cy-22), (cx, cy+22), (0, 255, 180), 1)
        cv2.circle(out, (cx, cy), 9, (0, 255, 180), 1)

        for det in detections:
            bbox = det.get('bbox')
            if not bbox:
                continue
            x1, y1, x2, y2 = self._clamp_bbox(bbox, fw, fh)
            if x2 <= x1 or y2 <= y1:
                continue

            threat = det['threat_level']
            color  = THREAT_COLORS.get(threat, (0, 200, 80))

            # Thin box
            cv2.rectangle(out, (x1, y1), (x2, y2), color, 1)

            # Corner marks
            cl = 8
            for px, py, dx, dy in [(x1,y1,1,1),(x2,y1,-1,1),(x1,y2,1,-1),(x2,y2,-1,-1)]:
                cv2.line(out, (px, py), (px+dx*cl, py), color, 2)
                cv2.line(out, (px, py), (px, py+dy*cl), color, 2)

            # Label — keep inside frame
            txt = f"{det['label']} {det['confidence']:.0%}"
            (tw, th), _ = cv2.getTextSize(txt, cv2.FONT_HERSHEY_SIMPLEX, 0.38, 1)
            lx = min(x1, fw - tw - 4)
            ly = max(th + 4, y1)
            cv2.rectangle(out, (lx, ly - th - 3), (lx + tw + 4, ly), color, -1)
            cv2.putText(out, txt, (lx + 2, ly - 1),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.38, (0, 0, 0), 1)

        cv2.putText(out, f"SAT SCAN | {len(detections)} targets",
                    (fw - 200, fh - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 255, 150), 1)
        return out

    # ── YOLO inference ────────────────────────────────────

    def _run_yolo(self, frame, module_name, conf_thresh=0.35, iou_thresh=None):
        if not self.model_loaded:
            return {'success': False, 'error': self.load_error or 'Model not loaded'}

        config  = self._get_module_config(module_name)
        targets = [t.lower() for t in config['targets']]
        
        kwargs = {'conf': conf_thresh, 'verbose': False}
        if iou_thresh is not None:
            kwargs['iou'] = iou_thresh
            
        results = self.model(frame, **kwargs)
        detections = []

        for result in results:
            if result.boxes is None:
                continue
            for box in result.boxes:
                cls_id     = int(box.cls[0])
                raw_label  = self.model.names[cls_id]
                confidence = float(box.conf[0])

                # Filter by targets (empty list = accept all)
                if targets and raw_label.lower() not in targets:
                    continue

                threat = self._classify_threat(raw_label, confidence, module_name)
                bbox   = box.xyxy[0].tolist()
                detections.append({
                    'label':       raw_label,
                    'confidence':  round(confidence, 3),
                    'threat_level': threat,
                    'bbox':        bbox,
                    'module':      module_name,
                })

        return {'success': True, 'detections': detections}

    # ── PUBLIC API ────────────────────────────────────────

    def process_frame(self, frame, module_name='smart_city', conf_thresh=None, iou_thresh=None):
        """Process a single video/webcam frame."""
        try:
            if frame is None or frame.size == 0:
                return {'success': False, 'error': 'Empty frame'}

            h, w = frame.shape[:2]
            if w > 640:
                scale = 640 / w
                frame = cv2.resize(frame, (640, int(h * scale)))

            conf = conf_thresh if conf_thresh is not None else 0.35
            result = self._run_yolo(frame, module_name, conf_thresh=conf, iou_thresh=iou_thresh)
            if not result['success']:
                return result

            annotated = self._draw_detections(frame, result['detections'], module_name)
            return {
                'success':        True,
                'detections':     result['detections'],
                'annotated_frame': annotated,
            }
        except Exception as e:
            logger.error(f'process_frame error: {e}')
            return {'success': False, 'error': str(e)}

    def process_image(self, image_path, module_name='smart_city', conf_thresh=None, iou_thresh=None):
        """Process an uploaded image file."""
        try:
            frame = cv2.imread(image_path)
            if frame is None:
                return {'success': False, 'error': 'Could not read image file'}
            return self.process_frame(frame, module_name, conf_thresh=conf_thresh, iou_thresh=iou_thresh)
        except Exception as e:
            logger.error(f'process_image error: {e}')
            return {'success': False, 'error': str(e)}

    def process_video_file(self, video_path, module_name='smart_city', max_frames=100, conf_thresh=None, iou_thresh=None):
        """Sample frames from an uploaded video and run YOLO on each."""
        cap = None
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return {'success': False, 'error': 'Could not open video file'}

            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            step  = max(1, total // max_frames) if total > max_frames else 1

            all_dets    = []
            frames_done = 0
            idx         = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                if idx % step == 0:
                    r = self.process_frame(frame, module_name, conf_thresh=conf_thresh, iou_thresh=iou_thresh)
                    if r['success']:
                        for d in r['detections']:
                            d['frame'] = idx
                            all_dets.append(d)
                        frames_done += 1
                    if frames_done >= max_frames:
                        break
                idx += 1

            # Deduplicate by label+threat
            seen, unique = set(), []
            for d in all_dets:
                k = (d['label'], d['threat_level'])
                if k not in seen:
                    seen.add(k)
                    unique.append(d)

            return {
                'success':          True,
                'detections':       unique,
                'total_detections': len(all_dets),
                'frames_processed': frames_done,
            }
        except Exception as e:
            logger.error(f'process_video_file error: {e}')
            return {'success': False, 'error': str(e)}
        finally:
            if cap:
                cap.release()

    def process_satellite_frame(self, frame, module_name='smart_city', conf_thresh=None, iou_thresh=None):
        """Run YOLO on satellite imagery with aerial-context label remapping."""
        try:
            if frame is None or frame.size == 0:
                return {'success': False, 'error': 'Empty frame'}

            if not self.model_loaded:
                return {'success': False, 'error': self.load_error or 'Model not loaded'}

            # Use lower confidence for aerial imagery (harder than street-level)
            conf = conf_thresh if conf_thresh is not None else 0.25
            kwargs = {'conf': conf, 'verbose': False}
            if iou_thresh is not None:
                kwargs['iou'] = iou_thresh

            results = self.model(frame, **kwargs)
            fh, fw  = frame.shape[:2]
            detections = []

            for result in results:
                if result.boxes is None:
                    continue
                for box in result.boxes:
                    cls_id     = int(box.cls[0])
                    raw_label  = self.model.names[cls_id]
                    confidence = float(box.conf[0])

                    # Remap to satellite-appropriate label
                    sat_label = SATELLITE_LABEL_MAP.get(raw_label, raw_label.title())

                    # Threat level from module config
                    config = self._get_module_config(module_name)
                    threat = config['threat_map'].get(raw_label.lower(), 'LOW')
                    if confidence > 0.70 and threat == 'LOW':
                        threat = 'MEDIUM'

                    bbox = box.xyxy[0].tolist()
                    detections.append({
                        'label':       sat_label,
                        'raw_label':   raw_label,
                        'confidence':  round(confidence, 3),
                        'threat_level': threat,
                        'bbox':        bbox,
                        'module':      'satellite',
                    })

            annotated = self._draw_satellite_detections(frame, detections, module_name)
            return {
                'success':        True,
                'detections':     detections,
                'annotated_frame': annotated,
            }
        except Exception as e:
            logger.error(f'process_satellite_frame error: {e}')
            return {'success': False, 'error': str(e)}
