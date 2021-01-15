"""write your views here"""
import json
import jwt
from rest_framework_jwt.serializers import jwt_payload_handler
from rest_framework import status,generics,permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny
from django.db.models.signals import post_save
from django.contrib.auth import user_logged_in, authenticate
from django.core.mail import send_mail
from django.shortcuts import render
from django.db.models import Q
from QuestionTaskProject import settings
from .serializers import RegisterSerializer, UserLoginSerializer, UserSerializer, MailSerializer
from .models import User, UserMail


class RegisterView(generics.CreateAPIView):
    """
    APIView to create an user
    """
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class LoginUserView(APIView):
    """
    APIView for user login
    """
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        """
        post request to user login
        :param request: request
        :return: user_details
        :rtype: dict.
        :raises: status.HTTP_403_FORBIDDEN
        """
        try:
            email = request.data['email']
            password = request.data['password']

            user = User.objects.get(email=email)
            if not user.check_password(password):
                return Response('invalid Credentials')
            if user:
                try:
                    payload = jwt_payload_handler(user)
                    token = jwt.encode(payload, settings.SECRET_KEY)
                    user_details = {
                        'name': user.name,
                        'token': token
                    }
                    authenticate(user)
                    return Response(user_details, status=status.HTTP_200_OK)

                except Exception as e:
                    raise e
            else:
                res = {
                    'error': 'can not authenticate with the given credentials'
                             ' or the account has been deactivated'
                }
                return Response(res, status=status.HTTP_403_FORBIDDEN)
        except KeyError:
            res = {'error': 'please provide a email and a password'}
            return Response(res)


class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    """
    Allow only authenticated users to access this url
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        """
        serializer to handle turning our `User` object into something that
        can be JSONified and sent to the client.

        :param request: user details
        :param args: dict
        :param kwargs: dict
        :return: serialized user data
        """
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        serializer_data = request.data.get('user', {})

        serializer = UserSerializer(
            request.user, data=serializer_data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class ComposeMail(APIView):
    """
    APIView to posting query to mentor by user

    Note: need to set EMAIL_HOST_USER and EMAIL_HOST_PASSWORD in settings.py file
    to send queries.
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = MailSerializer
    
    def post(self, request):
        """
        User should be able to post his query to mentor
        :param request: user details
        :return: Response
        """

        to = request.data.get('reciever')
        to=to[0]
        reciever = User.objects.get(email=to[0])
        if isinstance(reciever, tuple):
            reciever=reciever[0]
        subject = request.data.get('subject', None)
        usermail = UserMail.objects.create(
            sender=request.user,
            reciever=reciever,
            subject=subject[0],
            message=request.data['message'][0],
            attachment=request.data.get('attachment', None),
        )

        send_mail(
            usermail.subject,
            usermail.message,
            usermail.sender.email,
            [to],
        )

        return Response(
            json.dumps(
                {
                    'message': 'Mail has been delivered',
                    'sender': usermail.sender.email,
                    'reciever': usermail.reciever.email,
                    'sent-time': usermail.created_at,
                }
            )
        )



class GetAllUserMails(APIView):
    """
    APIView to get all User queries
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = MailSerializer

    def get(self, request, format=None):
        """
        get all queries posted by user
        :param request: mentor details
        :param format: Dict
        :return: queries list
        """
        if request.user.is_staff:
            queries = UserMail.objects.all()
            serializer = MailSerializer(queries, many=True)
            return Response(serializer.data)
        else:
            user = request.user
            queries = UserMail.objects.filter(Q(sender=user) | Q(reciever=user))
            serializer = MailSerializer(queries, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)


class SentMails(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = MailSerializer

    def get(self, request, format=None):
        user = request.user
        snippets = UserMail.objects.filter(sender=user)
        serializer = MailSerializer(snippets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)