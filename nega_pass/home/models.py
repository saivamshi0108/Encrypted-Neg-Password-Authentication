from django.db import models

# Create your models here.
class UserDetails(models.Model):
    email = models.CharField(max_length=122)
    hashed_password = models.BinaryField()
    negative_password = models.CharField(max_length = 1000)
    encrypted_password = models.BinaryField() 