# -*- coding: utf-8 -*-
"""
Created on Wed Feb  4 11:56:37 2026

@author: inder
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    DATABASE_PATH = os.getenv("DATABASE_PATH")