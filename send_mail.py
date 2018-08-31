import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from random import randint

def random_number():
    range_start = 10**(5)
    range_end = (10**6)-1
    return randint(range_start, range_end)

 
fromaddr = "sarveshmehta21@gmail.com"
toaddr = "sarvesh.mehta@research.iiit.ac.in"
number = random_number()
text = "Text ajkdsadbadbadboadb"
server = smtplib.SMTP('smtp.gmail.com',587)
server.starttls()
server.login(fromaddr, "notonpublic")
server.sendmail(fromaddr, toaddr, text)
server.quit()

