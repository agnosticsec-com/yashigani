"""
Yashigani CHS — GPU utilisation monitor.
Provider-agnostic: NVML (NVIDIA) → ROCm sysfs (AMD) → unavailable.
Never raises — always returns a GPUMetrics with available=False on failure.
Used by ResourceMonitor to include GPU pressure in the RPI formula.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ROCm sysfs paths (AMD)
_ROCM_DRM_BASE = Path("/sys/class/drm")
_ROCM_GPU_BUSY = "device/gpu_busy_percent"
_ROCM_VRAM_USED = "device/mem_info_vram_used"
_ROCM_VRAM_TOTAL = "device/mem_info_vram_total"


@dataclass
class GPUMetrics:
    available: bool = False
    backend: str = "unavailable"      # "nvml" | "rocm_sysfs" | "ollama_api" | "unavailable"
    device_count: int = 0
    # Aggregated across all detected devices (0.0–1.0)
    gpu_utilisation: float = 0.0      # compute utilisation
    gpu_memory_pressure: float = 0.0  # VRAM used / VRAM total
    # Per-device detail (list of dicts for Prometheus labels)
    devices: list[dict] = None        # type: ignore[assignment]

    def __post_init__(self):
        if self.devices is None:
            self.devices = []


def read_gpu_metrics(ollama_base_url: Optional[str] = None) -> GPUMetrics:
    """
    Attempt to read GPU metrics using available backends in priority order:
      1. NVML (NVIDIA) — most accurate, requires pynvml installed
      2. ROCm sysfs (AMD) — kernel sysfs, no library required
      3. Ollama /api/ps — reports whether models are GPU-loaded (proxy signal)
      4. Unavailable — returns zeros, available=False
    """
    metrics = _try_nvml()
    if metrics.available:
        return metrics

    metrics = _try_rocm_sysfs()
    if metrics.available:
        return metrics

    if ollama_base_url:
        metrics = _try_ollama_api(ollama_base_url)
        if metrics.available:
            return metrics

    return GPUMetrics(available=False, backend="unavailable")


# ---------------------------------------------------------------------------
# Backend: NVML (NVIDIA)
# ---------------------------------------------------------------------------

def _try_nvml() -> GPUMetrics:
    try:
        import pynvml  # type: ignore[import]
    except ImportError:
        return GPUMetrics(available=False, backend="unavailable")

    try:
        pynvml.nvmlInit()
        count = pynvml.nvmlDeviceGetCount()
        if count == 0:
            pynvml.nvmlShutdown()
            return GPUMetrics(available=False, backend="unavailable")

        devices: list[dict[str, Any]] = []
        total_util = 0.0
        total_mem_pressure = 0.0

        for i in range(count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)
            name = pynvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode()

            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)

            gpu_util = util.gpu / 100.0
            mem_pressure = mem_info.used / mem_info.total if mem_info.total > 0 else 0.0

            total_util += gpu_util
            total_mem_pressure += mem_pressure

            devices.append({
                "index": i,
                "name": name,
                "gpu_utilisation": round(gpu_util, 4),
                "memory_pressure": round(mem_pressure, 4),
                "memory_used_bytes": mem_info.used,
                "memory_total_bytes": mem_info.total,
            })

        pynvml.nvmlShutdown()

        return GPUMetrics(
            available=True,
            backend="nvml",
            device_count=count,
            gpu_utilisation=min(1.0, total_util / count),
            gpu_memory_pressure=min(1.0, total_mem_pressure / count),
            devices=devices,
        )
    except Exception as exc:
        logger.debug("NVML GPU read failed: %s", exc)
        try:
            pynvml.nvmlShutdown()
        except Exception:
            pass
        return GPUMetrics(available=False, backend="unavailable")


# ---------------------------------------------------------------------------
# Backend: ROCm sysfs (AMD)
# ---------------------------------------------------------------------------

def _try_rocm_sysfs() -> GPUMetrics:
    try:
        cards = sorted(_ROCM_DRM_BASE.glob("card*")) if _ROCM_DRM_BASE.exists() else []
        devices: list[dict[str, Any]] = []

        for card in cards:
            busy_path = card / _ROCM_GPU_BUSY
            vram_used_path = card / _ROCM_VRAM_USED
            vram_total_path = card / _ROCM_VRAM_TOTAL

            if not busy_path.exists():
                continue

            try:
                gpu_util = int(busy_path.read_text().strip()) / 100.0
            except (ValueError, OSError):
                continue

            mem_pressure = 0.0
            mem_used = 0
            mem_total = 0
            if vram_used_path.exists() and vram_total_path.exists():
                try:
                    mem_used = int(vram_used_path.read_text().strip())
                    mem_total = int(vram_total_path.read_text().strip())
                    mem_pressure = mem_used / mem_total if mem_total > 0 else 0.0
                except (ValueError, OSError):
                    pass

            devices.append({
                "index": len(devices),
                "name": card.name,
                "gpu_utilisation": round(gpu_util, 4),
                "memory_pressure": round(mem_pressure, 4),
                "memory_used_bytes": mem_used,
                "memory_total_bytes": mem_total,
            })

        if not devices:
            return GPUMetrics(available=False, backend="unavailable")

        count = len(devices)
        avg_util = sum(d["gpu_utilisation"] for d in devices) / count
        avg_mem = sum(d["memory_pressure"] for d in devices) / count

        return GPUMetrics(
            available=True,
            backend="rocm_sysfs",
            device_count=count,
            gpu_utilisation=min(1.0, avg_util),
            gpu_memory_pressure=min(1.0, avg_mem),
            devices=devices,
        )
    except Exception as exc:
        logger.debug("ROCm sysfs GPU read failed: %s", exc)
        return GPUMetrics(available=False, backend="unavailable")


# ---------------------------------------------------------------------------
# Backend: Ollama /api/ps (proxy signal — model loaded = GPU in use)
# ---------------------------------------------------------------------------

def _try_ollama_api(base_url: str) -> GPUMetrics:
    """
    Queries Ollama /api/ps to check if any model is loaded with GPU offload.
    This is a proxy signal only — does not return utilisation percentages.
    Returns available=True with estimated pressure if GPU is in use.
    """
    import urllib.request, json

    try:
        url = base_url.rstrip("/") + "/api/ps"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())

        models = data.get("models", [])
        gpu_layers = 0
        total_size = 0
        for m in models:
            details = m.get("details", {})
            gpu_layers += details.get("num_gpu", 0)
            total_size += m.get("size_vram", 0)

        if gpu_layers == 0 and total_size == 0:
            return GPUMetrics(available=False, backend="unavailable")

        # Use VRAM loaded as a proxy for memory pressure
        # No reliable total VRAM from this endpoint — use 0.5 as conservative estimate
        mem_pressure = min(1.0, total_size / (8 * 1024 ** 3)) if total_size > 0 else 0.3
        util = min(1.0, gpu_layers / 40.0)  # 40 layers ≈ full 7B model

        return GPUMetrics(
            available=True,
            backend="ollama_api",
            device_count=1,
            gpu_utilisation=util,
            gpu_memory_pressure=mem_pressure,
            devices=[{
                "index": 0,
                "name": "ollama_inferred",
                "gpu_utilisation": round(util, 4),
                "memory_pressure": round(mem_pressure, 4),
                "memory_used_bytes": total_size,
                "memory_total_bytes": 0,
            }],
        )
    except Exception as exc:
        logger.debug("Ollama API GPU probe failed: %s", exc)
        return GPUMetrics(available=False, backend="unavailable")
