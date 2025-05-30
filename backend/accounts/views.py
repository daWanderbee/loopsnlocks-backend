import random
import json
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from .models import CustomUser  # your custom user model
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required

@csrf_exempt
def request_otp_signup(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        if CustomUser.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already registered'}, status=400)

        otp = str(random.randint(100000, 999999))

        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_verified=False,
            otp=otp,
            otp_expiry=timezone.now() + timedelta(minutes=10)
        )

        send_mail(
            'Your OTP Code',
            f'Your OTP is {otp}',
            'asmita2018fzd@gmail.com',
            [email],
            fail_silently=False,
        )

        return JsonResponse({'detail': 'OTP sent to email'})


@csrf_exempt
def verify_otp_and_register(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        otp_input = data.get('otp')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User not found'+ email,'email': email},status=404)

        if user.otp == otp_input and timezone.now() < user.otp_expiry:
            user.is_verified = True
            user.otp = None
            user.otp_expiry = None
            user.save()
            return JsonResponse({'detail': 'Account verified'})
        else:
            return JsonResponse({'error': 'Invalid or expired OTP'}, status=400)

DEFAULT_BACKEND = 'django.contrib.auth.backends.ModelBackend'

@csrf_exempt
def request_otp_login(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
        email = data.get('email')
        user = CustomUser.objects.get(email=email)
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Invalid JSON or missing email'}, status=400)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    if not user.is_verified:
        return JsonResponse({'error': 'Email not verified'}, status=403)

    otp = str(random.randint(100000, 999999))
    user.otp = otp
    user.otp_expiry = timezone.now() + timedelta(minutes=10)
    user.save()

    send_mail(
        'Your Login OTP',
        f'Your OTP is {otp}',
        'asmita2018fzd@gmail.com',
        [email],
        fail_silently=False,
    )

    return JsonResponse({'detail': 'OTP sent to email'})


@csrf_exempt
def login_user(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        otp_input = data.get('otp')
    except (json.JSONDecodeError, KeyError):
        return JsonResponse({'error': 'Invalid JSON or missing fields'}, status=400)

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    if not user.is_verified:
        return JsonResponse({'error': 'Email not verified'}, status=403)

    # If password is provided, authenticate with it
    if password:
        user_auth = authenticate(request, email=email, password=password)
        if user_auth:
            login(request, user_auth)  # logs in and creates session
            return JsonResponse({'detail': 'Login successful via password'})
        else:
            return JsonResponse({'error': 'Invalid password'}, status=400)

    # If OTP is provided, verify and login
    if otp_input:
        if user.otp == otp_input and timezone.now() < user.otp_expiry:
            user.backend = DEFAULT_BACKEND  # Set backend explicitly
            login(request, user)
            # Clear OTP after successful login
            user.otp = None
            user.otp_expiry = None
            user.save()
            return JsonResponse({'detail': 'Login successful via OTP'})
        else:
            return JsonResponse({'error': 'Invalid or expired OTP'}, status=400)

    return JsonResponse({'error': 'Please provide password or OTP'}, status=400)

@csrf_exempt
def logout_view(request):
    if request.method == "POST":  # Usually logout is POST for safety
        logout(request)  # This clears the session
        return JsonResponse({'detail': 'Logged out successfully'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

def check_username(request):
    username = request.GET.get('username', '').strip()
    if not username:
        return JsonResponse({'error': 'Username parameter is required'}, status=400)
    
    is_taken = CustomUser.objects.filter(username=username).exists()
    return JsonResponse({'available': not is_taken})

def whoami(request):
    if request.user.is_authenticated:
        return JsonResponse({
            "is_authenticated": True,
            "username": request.user.username,
            "email": request.user.email,
        })
    else:
        return JsonResponse({
            "is_authenticated": False,
        }, status=200)  # 200 is okay here — no redirect