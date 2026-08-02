"""Structured logging system for Frappe Security Scanner."""
from __future__ import annotations

import logging
import sys


def get_logger(name: str = "scanner") -> logging.Logger:
	"""Retrieve or configure the central scanner logger."""
	logger = logging.getLogger(name)
	if not logger.handlers:
		handler = logging.StreamHandler(sys.stdout)
		formatter = logging.Formatter(
			fmt="[%(asctime)s] %(levelname)s [%(name)s]: %(message)s",
			datefmt="%Y-%m-%d %H:%M:%S",
		)
		handler.setFormatter(formatter)
		logger.addHandler(handler)
		logger.setLevel(logging.INFO)
	return logger


logger = get_logger("scanner")
