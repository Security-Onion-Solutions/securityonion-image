from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField


class DefaultForm(FlaskForm):
   esindex = StringField('esindex')
   esid = StringField('esid')
