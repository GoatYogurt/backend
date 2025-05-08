from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer

from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework import generics

from rest_framework.views import APIView
from rest_framework import status
from .serializers import RegisterSerializer, CallTokenSerializer

import stream_chat
from django.conf import settings

class AuthTokenView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AuthTokenSerializer

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Token.objects.select_related('user').all()
        return Token.objects.none()

    def get(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response('You do not have permission to view all tokens', status=status.HTTP_403_FORBIDDEN)
        
        tokens = self.get_queryset()
        data = [
            {
                'user_id': token.user.id,
                'username': token.user.username,
                'email': token.user.email,
                'token': token.key
            }
            for token in tokens
        ]
        return Response(data)
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })


class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({"message": "User registered successfully.",
                              "token": token.key,
                            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        return Response({
            "username": "string",
            "email": "string (optional)",
            "password": "string"
        })


class LoginView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = AuthTokenSerializer  # or your own LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            "token": token.key,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
        })

    def get(self, request):
        return Response({
            "username": "your_username",
            "password": "your_password"
        })


class CallTokenView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = CallTokenSerializer

    def get(self, request):
        server_client = stream_chat.StreamChat(
            api_key=settings.API_KEY, 
            api_secret=settings.API_SECRET
        )

        token = server_client.create_token(request.user.username)
        return Response(token)