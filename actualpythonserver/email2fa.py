# Import smtplib for the actual sending function
import smtplib
PASSWORD = "expm mhrl fekg qghf"
EMAIL="speakappveri@gmail.com"

# Import the email modules we'll need
from email.mime.text import MIMEText
def send_email_2fa(email : str, verification_code : str):
    """
    Send an email to the specified email with the verification code
    :param email: the email to send the code to
    :param verification_code: the code to send
    :return: None
    """
    server = smtplib.SMTP('smtp.gmail.com',587)
    server.starttls()
    server.login(EMAIL, PASSWORD)
    body = "Your Verification code is\n" + verification_code
    subject ="Verification code for SpeakApp"
    message = f'subject:{subject}\n\n{body}'
    server.sendmail(EMAIL, email, message)