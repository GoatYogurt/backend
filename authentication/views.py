import uuid

from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer

from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework import generics

from rest_framework.views import APIView
from rest_framework import status
from .serializers import RegisterSerializer, CallTokenSerializer

import stream_chat
import getstream
from getstream.models import UserRequest
from django.conf import settings

client = getstream.Stream(
    api_key=settings.API_KEY,
    api_secret=settings.API_SECRET,
)
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
        
        auth_tokens = self.get_queryset()
        data = [
            {
                'user_id': token.user.id,
                'username': token.user.username,
                'email': token.user.email,
                'token': token.key
            }
            for token in auth_tokens
        ]
        return Response(data)
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        auth_token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': auth_token.key,
            'user_id': user.pk,
            'email': user.email
        })


class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer
    
    def get(self, request):
        return Response({
            "username": "string",
            "email": "string (optional)",
            "password": "string"
        })

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            client.upsert_users(
                UserRequest(
                    id=user.username, name=user.username, role="user"
                ),
            )
            stream_token = client.create_token(user_id=user.username)
            auth_token, created = Token.objects.get_or_create(user=user)
            return Response({"username": user.username,
                              "auth_token": auth_token.key,
                              "stream_token": stream_token
                            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = AuthTokenSerializer  # or your own LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        auth_token, created = Token.objects.get_or_create(user=user)
        stream_token = client.create_token(user_id=user.username)

        return Response({
            "username": user.username,
            "auth_token": auth_token.key,
            "stream_token": stream_token,
            # "user_id": user.id,
            # "email": user.email,
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
        client = getstream.Stream(
            api_key=settings.API_KEY,
            api_secret=settings.API_SECRET,
        )
        
        stream_token = client.create_token(user_id=request.user.username)
        return Response({ "stream_token": stream_token })


class GuestUserView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        guest_id = f"Guest-{uuid.uuid4()}"
        stream_token = client.create_token(user_id=guest_id, expiration=3600)

        return Response({
            "guest_id": guest_id,
            "stream_token": stream_token
        })


class CallQueryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        calls = client.video.query_calls(
            filter_conditions={'ongoing': {'$eq': True}}
        )
        # print(calls.data.calls)
        # response = client.video.query_calls(
        #     sort= [SortParamRequest(field: 'starts_at', direction: -1)],
        #     limit=2,
        # )
        call_ids = []
        for call in calls.data.calls:
            call_ids.append(call.call.id)
            # print('\n')
        return Response({ "calls": call_ids })

