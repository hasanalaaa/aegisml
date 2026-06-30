import logging

logger = logging.getLogger(__name__)

def send_threat_alert(model_name: str, author: str, severity: str, scan_id: str):
    # Mocking email/alert notification
    logger.warning(f"ALERT: High/Critical threat found in model '{model_name}' by '{author}'. Severity: {severity}. Scan ID: {scan_id}")
    # Integration with Resend/SendGrid could go here
    return True
