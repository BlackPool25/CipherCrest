"""risk_train_plot — re-export from risk_plot for back-compat."""

from assessment.risk_plot import save_calibration_plot, save_pr_plot

__all__ = ["save_calibration_plot", "save_pr_plot"]
