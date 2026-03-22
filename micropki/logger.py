import logging
import sys

def setup_logging(log_file=None, level=logging.INFO):
    """Configure logging for MicroPKI."""
    logger = logging.getLogger('micropki')
    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger
    logger.setLevel(level)
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
                                  datefmt='%Y-%m-%dT%H:%M:%S')
    if log_file:
        fh = logging.FileHandler(log_file, mode='a')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    else:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(formatter)
        logger.addHandler(sh)
    return logger