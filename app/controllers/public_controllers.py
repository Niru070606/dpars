from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db

public_bp = Blueprint('public', __name__)

@public_bp.route('/public-dashboard')
def public():
    return render_template('public/public_dashboard.html')