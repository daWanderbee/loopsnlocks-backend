from allauth.account.signals import user_logged_in
from allauth.socialaccount.models import SocialAccount
from django.dispatch import receiver

@receiver(user_logged_in)
def mark_google_users_verified(request, user, **kwargs):
    if SocialAccount.objects.filter(user=user, provider="google").exists():
        if not user.is_verified:
            user.is_verified = True
            user.save()
