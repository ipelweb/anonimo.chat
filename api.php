<?php
/**
 * Anonimo.chat – Public API for anonymous chat sessions.
 */

require_once __DIR__ . '/inc/php/global.php'; 

header('Content-Type: application/json');
header('X-Robots-Tag: noindex, nofollow', true);

// CORS
header('Access-Control-Allow-Origin: https://'.AC_DOMAIN);
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');

// Preflight (no body)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; } 

try {
    $redis = new Redis();
    $redis->connect(AC_REDIS_HOST, AC_REDIS_PORT);
    $redis->auth(AC_REDIS_PASS);
} catch (RedisException $e) {
    error_log("Redis error: $e->getMessage()"); http_response_code(500); exit(json_encode(['error' => 'Redis error' ]));
}

$chat_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_REGEXP, [ 'options' => ['regexp' => '/^[a-f0-9]{32}$/'] ]);
if (!$chat_id) { error_log("Invalid ChatID"); http_response_code(400); exit(json_encode(['error' => 'Invalid ChatID'])); }
if (!isset($_SESSION['user_id'])) { error_log("Invalid UserID"); http_response_code(403); exit(json_encode(['error' => 'Invalid UserID'])); }
$user_id = $_SESSION['user_id'];

$method = $_SERVER['REQUEST_METHOD'] ?? '';
switch ($method) {
    case 'GET': api_get( $redis, $chat_id, $user_id ); break;
    case 'POST': api_post( $redis, $chat_id, $user_id ); break; 
    case 'DELETE': api_delete( $redis, $chat_id, $user_id ); break;
    default: error_log("Invalid method"); http_response_code(405); exit(json_encode( ['error' => 'Invalid method'] ));
}

function api_post( $redis, $chat_id, $user_id ){

    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === false) {
        error_log("Unsupported Media Type"); http_response_code(415); exit(json_encode(['error'=>'Unsupported Media Type']));
    }

    $metaKey = "chat:$chat_id:meta";
    $messagesKey = "chat:$chat_id:messages";
    $usersKey = "chat:$chat_id:users";

    $data = json_decode(file_get_contents('php://input'), true);

    if (!is_array($data)) { error_log("Invalid Payload"); http_response_code(400); exit(json_encode(['error'=>'Invalid Payload'])); }

    if( !isset($_SESSION['csrf']) || !isset( $data['csrf'] ) || !is_string($data['csrf'] ) || !hash_equals($_SESSION['csrf'], $data['csrf'] ) ) {
        error_log("Invalid CSRF"); http_response_code(403); exit(json_encode(['error' => 'Invalid CSRF'])); 
    }

    $message = trim(strip_tags($data['message']) ?? ''); 

    if (empty($message)) { http_response_code(400); exit(json_encode(['error' => 'Empty message'])); }

    if (mb_strlen($message, 'UTF-8') > 1000) { error_log("Message is too big"); http_response_code(400); exit(json_encode(['error' => 'Message is too big (max 1000 characters'])); }

    // ip rate limit 
    $limitMax  = 20; 
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ipLimitKey = "chat:$chat_id:limit_ip:" . hash( 'sha256', $ip );
    $ipCount = $redis->incr($ipLimitKey);
    if ($ipCount === 1) { $redis->expire($ipLimitKey, 60); } // first > set TTL 60 sec
    if ($ipCount > $limitMax) { error_log("Rate limit IP"); http_response_code(429); exit(json_encode(['error' => "Too many requests from IP"])); }

    // msg rate limit
    $limitKey  = "chat:$chat_id:limit_msg:$user_id";
    $count = $redis->incr($limitKey);
    if ($count === 1) { $redis->expire($limitKey, 60); } // first > set TTL 60 sec
    if ($count > $limitMax) { error_log("Rate limit msg"); http_response_code(429); exit(json_encode([ 'error' => "Messages limit exceeded (max $limitMax/minute)" ])); }

    // double msg
    $hashKey = "chat:$chat_id:limit_same:$user_id";
    $msgHash = hash('sha256', $message);
    $lastMsgData = $redis->get($hashKey);
    if ($lastMsgData) {
        [$prevHash, $prevTime] = explode('|', $lastMsgData);
        if ($prevHash === $msgHash && (time() - (int)$prevTime) < 10) {
            error_log("Duplicated message"); http_response_code(429); exit(json_encode(['error' => 'Duplicated message']));
        }
    }
    $redis->setex($hashKey, 30, "$msgHash|" . time()); // save last msg

    // no meta > new chat
    if (!$redis->exists($metaKey)) {
        $redis->hMSet($metaKey, [
            'created_at' => time(),
            'admin' => $user_id,
        ]);
        $redis->incr('counter:chats');
    }

    // 24h expire (TTL) 
    $redis->expire($metaKey, 86400);
    $redis->expire($messagesKey, 86400);
    $redis->expire($usersKey, 86400);

    // set nickname
    if(!$redis->hExists($usersKey, $user_id)) {

        if( !preg_match('/^[A-Za-z0-9 _-]{3,20}$/', $message)) { exit(json_encode(['error'=>'Invalid Nickname'])); }

        $redis->hSet($usersKey, $user_id, $message); 
        $redis->incr('counter:users');
        
        $is_admin = $redis->hGet($metaKey, 'admin') === $user_id;

        $redis->rPush($messagesKey, json_encode([
            'time' => time(),
            'type' => 'system',
            'message' => encryptMessage( ( $is_admin ? "New chat started by $message" : "$message joined the chat" ), $chat_id ),
        ]));

        exit(json_encode([
            'success' => true,
            'type' => 'nickname_set',
            'nickname' => $message,
            'role' => $is_admin ? 'admin' : 'user'
        ]));
    }

    // save message
    $nickname = $redis->hGet($usersKey, $user_id);

    $is_admin = $redis->hGet($metaKey, 'admin') === $user_id;

    $encryptedMessage = encryptMessage($message, $chat_id);

    $redis->rPush($messagesKey, json_encode([
        'time' => time(),
        'user_id' => $user_id,
        'nickname' => $nickname,
        'message' => $encryptedMessage,
    ]));
    $redis->incr('counter:messages');

    echo json_encode(['success' => true, 'type' => 'message_sent']);
}

function api_get($redis, $chat_id, $user_id){

    $metaKey = "chat:$chat_id:meta";
    $messagesKey = "chat:$chat_id:messages";
    $usersKey = "chat:$chat_id:users";

    // no nickname > hide chat
    if (!$redis->hExists($usersKey, $user_id)) {
        exit(json_encode([
            'success' => false,
            'error' => 'Nickname not set',
            'require_nickname' => true
        ]));
    }

    // with nickname > show chat
    $rawMessages = $redis->lRange($messagesKey, 0, -1);
    $users = $redis->hGetAll($usersKey);

    // chat messages 
    $messagesHtml = '';
    foreach ($rawMessages as $raw) {
        $msg = json_decode($raw, true);

        if (!isset($msg['message'])) continue;
        
        $msg['message'] = decryptMessage($msg['message'], $chat_id);
        $santizedMsg = htmlspecialchars($msg['message'], ENT_QUOTES, 'UTF-8');
        $type = $msg['type'] ?? 'user';
        $class = 'message';

        if ($type === 'system') {
            $class .= ' system-message';
            $text = "[" . date('H:i', $msg['time']) . "] $santizedMsg";
        } else {
            $nickname = htmlspecialchars($msg['nickname'] ?? '');
            $text = "[" . date('H:i', $msg['time']) . "] <b>$nickname</b>: $santizedMsg";
            if (($msg['user_id'] ?? '') === $user_id) { $class .= ' my-message'; }
        }
        $messagesHtml .= "<div class=\"$class\">$text</div>";
    }

    // users
    $usersHtml = '';
    $admin_id = $redis->hGet($metaKey, 'admin');
    foreach ($users as $uid => $nick) {
        $class = (( $uid ?? '') === $user_id) ? "my-message" : '';
        $admin = (($admin_id ?? '') === $uid) ? " (admin)" : '';
        $usersHtml .= "<li class='$class'><i class='fa-solid fa-user'></i>&nbsp; <b>" . htmlspecialchars($nick) . "</b>$admin</li>";
    }

    echo json_encode([
        'success' => true,
        'messages_html' => $messagesHtml,
        'users_html' => $usersHtml,
        'users_total' => $redis->hLen($usersKey), // count users
    ]);
}

function api_delete($redis, $chat_id, $user_id){

    $data = json_decode(file_get_contents('php://input'), true);

    if (!is_array($data)) { error_log("Invalid Payload"); http_response_code(400); exit(json_encode(['error'=>'Invalid Payload'])); }

    if( !isset($_SESSION['csrf']) || !isset( $data['csrf'] ) || !is_string($data['csrf'] ) || !hash_equals($_SESSION['csrf'], $data['csrf'] ) ) {
        error_log("Invalid CSRF"); http_response_code(403); exit(json_encode(['error' => 'Invalid CSRF'])); 
    }

    if (!$redis->exists("chat:$chat_id:meta")) { http_response_code(400); exit(json_encode(['error' => 'Invalid Chat'])); }

    if( !$redis->hExists("chat:$chat_id:users", $_SESSION['user_id'] ) ) { http_response_code(403); exit(json_encode(['error' => 'Invalid User'])); }

    if( $redis->hGet("chat:$chat_id:meta", 'admin') !== $_SESSION['user_id'] ) { error_log("Invalid Admin"); http_response_code(403); exit(json_encode(['error' => 'Invalid Admin'])); }

    // delete (pipeline for efficiency)
    $iterator = null;
    while (true) {
        $keys = $redis->scan($iterator, "chat:$chat_id:*", 100);
        if ($keys === false || empty($keys)) { break; }

        $redis->multi();
        foreach ($keys as $key) { $redis->del($key); }
        $redis->exec();

        if ($iterator === 0) { break; }
    }

    exit(json_encode([ 'success' => true ]));
}
