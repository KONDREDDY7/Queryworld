from django.urls import path
from . import views



urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='registration'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('user/', views.UserRetrieveUpdateAPIView.as_view(), name='user'),
    path('compose/', views.ComposeMail.as_view(), name='compose'),
    path('Querydashboard/', views.GetAllUserMails.as_view(), name='mails'),
    path('mails/sent/', views.SentMails.as_view(), name='mails'),

]
