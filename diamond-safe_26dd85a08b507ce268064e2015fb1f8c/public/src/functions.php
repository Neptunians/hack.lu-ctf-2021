<?php
function ms($s){
    return htmlspecialchars($s, ENT_QUOTES);
}

function print_footer(){
    printf("<div class='footer'> %s | STOINKS AG</div><br>" , @date('Y'));
}

function error($error){
    printf("<div class='alert alert-danger'><strong>%s</strong></div>", ms($error));
    print_footer();
    exit();
}

function success($success){
    printf("<div class='alert alert-success'><strong>%s</strong></div>", ms($success));
}

function get_ip(){
    if (!empty($_SERVER['X-Real-IP'])) {
        return $_SERVER['X-Real-IP'];
    } 
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } 
    else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

function redirect($url, $s=0) {
    echo "<meta http-equiv='refresh' content='$s;$url'>";
}


function gen_secure_url($f){
    $secret = getenv('SECURE_URL_SECRET');
    $hash = md5("{$secret}|{$f}|{$secret}");
    $url = "download.php?h={$hash}&file_name={$f}";
    return $url;
}

function check_url(){
    // NEPTUNIAN
    echo "SERVER: " . var_dump($_SERVER) . "\n";
    echo "QUERYSTRING: " . $_SERVER['QUERY_STRING'] . "\n";

    // fixed bypasses with arrays in get parameters
    $query  = explode('&', $_SERVER['QUERY_STRING']);

    // NEPTUNIAN
    echo var_dump($query) . "\n";

    $params = array();
    foreach( $query as $param ){
        // prevent notice on explode() if $param has no '='
        if (strpos($param, '=') === false){
            $param += '=';
        }
        list($name, $value) = explode('=', $param, 2);
        $params[urldecode($name)] = urldecode($value);

        // NEPTUNIAN
        echo "Encoded => " . $name . ": " . $value . "\n";
        echo "Decoded => " . urldecode($name) . ": " . urldecode($value) . "\n";
    }

    // NEPTUNIAN
    echo var_dump($params) . "\n";

    // error_log(var_dump($params));
    // syslog(LOG_INFO, var_dump($params));
    // fwrite(STDOUT, var_dump($params));

    if(!isset($params['file_name']) or !isset($params['h'])){
        // NEPTUNIAN
        echo "Params not found!! => file_name and h\n";
        return False;
    }

    $secret = getenv('SECURE_URL_SECRET');
    $hash = md5("{$secret}|{$params['file_name']}|{$secret}");

    // NEPTUNIAN
    echo "Calculated Hash: " . $hash . "\n";
    echo "Sent Hash:       " . $params['h'] . "\n";

    if($hash === $params['h']){
        // NEPTUNIAN
        echo "PASSED!" . $params['h'] . "\n";
        return True;
    }
    // NEPTUNIAN
    echo "NOT PASSED!" . $params['h'] . "\n";

    return False;
    
}

?>