from django.contrib import admin
from .models import User, UserMail

# Register your models here.
admin.site.register(User)
admin.site.register(UserMail)
