# Generated by Django 5.2.1 on 2025-05-30 09:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_customuser_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='role',
            field=models.CharField(choices=[('creator', 'Creator'), ('learner', 'Learner')], default='learner', max_length=50),
        ),
    ]
