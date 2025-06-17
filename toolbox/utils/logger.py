import logging

logging.basicConfig(filename="toolbox.log", level=logging.INFO)

def log(message):
    logging.info(message)