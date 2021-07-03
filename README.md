# JwtAuthentication With RefreshToekn
actoin implemented : 

```Login```

```Register```

```Recovery Password```

```Rest Password```

```Refresh Token```


# Note
The Alomost Complite And Secure  Authentication Api Source Code

--Please after download source code run ```Update-database``` in packege manage console to create database from migrations.

--For sending email write your email and password in ```Utilites/SendEmail.cs``` file.

## Note For ```Recovery Password ```
This Step By Step For You:

1- Call ```Get``` Action and pass Email.

2- Implemnt Your own view for getting NewPassword from user.

3- Change link url in line ```193``` in authentication controller and set that where your Recovery Password view is.

4- In Your Recovery Password view your must save ```token``` and ```email``` paramter. those values is in sended email link and seted in line ```193``` but you can copy use ```PostMan``` for testing.

5- Get NewPassword from user and in ```Post``` request set valuse on body and send to ```RecoveryPassword``` endpoint with below json format

````
{
    "Email":"",
    "Token":"",
    "NewPassword":""
}
````

