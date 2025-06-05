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
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');

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
    case 'PUT': api_actions($redis, $chat_id, $user_id); break;
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
        if ($prevHash === $msgHash && (time() - (int)$prevTime) < 60) {
            error_log("Duplicated message"); http_response_code(429); exit(json_encode(['error' => 'Duplicated message']));
        }
    }
    $redis->setex($hashKey, 60, "$msgHash|" . time()); // save last msg

    // spam same link
    if (preg_match('#https?://[^\s<>()"]+#i', $message, $urlMatch)) {
        if (parse_url($urlMatch[0], PHP_URL_HOST) !== AC_DOMAIN) { // allow share chat links
            $currentPath = parse_url($urlMatch[0], PHP_URL_SCHEME) . '://' . parse_url($urlMatch[0], PHP_URL_HOST) . parse_url($urlMatch[0], PHP_URL_PATH);
            $recentMsgs = $redis->lRange($messagesKey, -30, -1); // last 30 messages
            foreach (array_reverse($recentMsgs) as $raw) {
                $msg = json_decode($raw, true);
                if (!is_array($msg)) continue;
                if (($msg['user_id'] ?? null) !== $user_id || !isset($msg['message'])) continue; // user msg only
                if (preg_match('#https?://[^\s<>()"]+#i', decryptMessage($msg['message'], $chat_id), $pastUrlMatch)) {
                    $pastPath = parse_url($pastUrlMatch[0], PHP_URL_SCHEME) . '://' .parse_url($pastUrlMatch[0], PHP_URL_HOST) . parse_url($pastUrlMatch[0], PHP_URL_PATH);
                    if ($pastPath === $currentPath) { http_response_code(429); exit(json_encode(['error' => 'Duplicated link'])); }
                }
            }
        }
    }

    // no meta > new chat
    if (!$redis->exists($metaKey)) {
        $redis->hMSet($metaKey, [
            'created_at' => time(),
            'admin' => $user_id,
        ]);
        $redis->incr('counter:chats');
    }
    $redis->expire($metaKey, 86400); 

    // set nickname
    if(!$redis->hExists($usersKey, $user_id)) {

        if (!preg_match('/^[\p{L}\p{N} _\-]{3,20}$/u', $message)) {exit(json_encode(['error'=>'Invalid Nickname'])); } 
    
        // add user
        $redis->hSet($usersKey, $user_id, $message); 
        $redis->incr('counter:users');

        $redis->setex("chat:$chat_id:online:$user_id", 1200, 1); // online 20 min
        
        $is_admin = $redis->hGet($metaKey, 'admin') === $user_id;

        $sys_msg = $is_admin ? "New chat started by $message" : "$message joined the chat";

        $redis->rPush($messagesKey, json_encode([
            'time' => time(),
            'type' => 'system',
            'message' => encryptMessage( $sys_msg, $chat_id ),
        ]));

        // 24h expire (TTL) 
        $redis->expire($metaKey, 86400);
        $redis->expire($messagesKey, 86400);
        $redis->expire($usersKey, 86400);

        exit(json_encode([
            'success' => true,
            'type' => 'nickname_set',
            'nickname' => $message,
            'role' => $is_admin ? 'admin' : 'user'
        ]));
    }

    $nickname = $redis->hGet($usersKey, $user_id);
    $is_admin = $redis->hGet($metaKey, 'admin') === $user_id;

    $redis->setex("chat:$chat_id:online:$user_id", 1200, 1); // online 20 min

    // command /invite [nickname] [link] (daily public chat only)
    if ( $redis->get("chat:stg:day") == $chat_id && preg_match('#^/invite\s+([\w\-]{3,20})\s+(https://'.preg_quote(AC_DOMAIN).'/[a-f0-9]{32})$#', $message, $matches)) {
        $targetNick = $matches[1];
        $link = $matches[2];
       
        $targetUserId = array_search($targetNick, $redis->hGetAll($usersKey)); 
        if (!$targetUserId || $targetUserId === $user_id || $targetNick === $nickname ) { exit(json_encode(['error' => 'Invalid Command (user)'])); } // check user
        if( $link == "https://".AC_DOMAIN."/$chat_id" ) { exit(json_encode(['error' => 'Invalid Command (link)'])); } // check link
        if( !$redis->hExists("chat:".substr($link,-32).":users", $user_id) ) { exit(json_encode(['error' => 'Invalid Command (chat)'])); } // check chat

        $redis->rPush($messagesKey, json_encode([
            'time' => time(),
            'type' => 'invite',
            'user_id' => $user_id,
            'nickname' => $nickname,
            'message' => encryptMessage($link, $chat_id),
            'to' => $targetUserId, //$targetNick,
        ]));

        echo json_encode(['success' => true, 'type' => 'invite_sent']);
        return;

    } elseif( substr( $message, 0, 1 ) == '/' ) { exit(json_encode(['error'=>'Invalid Command'])); } 

    // save message
    $encryptedMessage = encryptMessage($message, $chat_id);
    $redis->rPush($messagesKey, json_encode([
        'time' => time(),
        'user_id' => $user_id,
        'nickname' => $nickname,
        'message' => $encryptedMessage,
    ]));
    $redis->incr('counter:messages');

    // 24h expire (TTL) 
    $redis->expire($metaKey, 86400);
    $redis->expire($messagesKey, 86400);
    $redis->expire($usersKey, 86400);

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
        $nickname = htmlspecialchars($msg['nickname'] ?? '');
        $type = $msg['type'] ?? 'user';
        $class = 'message';

        if ($type === 'invite') {
            if (($msg['to'] ?? '') !== $user_id) continue; // show only to target usr
            if ($redis->sIsMember("chat:$chat_id:invite:$user_id", hash('sha256', AC_SALTKEY.$nickname) )) continue; // seen
            $messagesHtml .= "<div class=\"message invite-message system-message\" data-invite=\"".hash('sha256', AC_SALTKEY.$nickname)."\" data-link=\"$santizedMsg\">[" . date('H:i', $msg['time']) . " UTC] INVITE: <b>$nickname</b> invited you to join a private chat. <button class='acceptBtn'>Join</button> <button class='declineBtn'>Dismiss</button></div>";
            continue;
        }

        $santizedMsg = formatMessage( $santizedMsg ); // add a href, img, bold

        if ($type === 'system') {
            $class .= ' system-message';
            if( !$messagesHtml ) { $class .= ' sticky-message'; } // first msg pinned
            $text = "[" . date('H:i', $msg['time']) . " UTC] $santizedMsg";
        } else {
            $text = "[" . date('H:i', $msg['time']) . " UTC] <b>$nickname</b>: $santizedMsg";
            if (($msg['user_id'] ?? '') === $user_id) { $class .= ' my-message'; }
        }
        $messagesHtml .= "<div class=\"$class\">$text</div>";
    }

    // users
    $usersHtml = '';
    $admin_id = $redis->hGet($metaKey, 'admin');
    foreach ($users as $uid => $nick) {
        if( !$redis->exists("chat:$chat_id:online:$user_id") ) { $tag = " (away)"; $class = "disabled-message"; } // online 20 min
        if( ( $uid ?? '') === $user_id) { $class = "my-message"; }
        if( ($admin_id ?? '') === $uid) { $tag = " (admin)"; $class = ""; }
        $usersHtml .= "<li class='$class'><i class='fa-solid fa-user'></i>&nbsp; <b>" . htmlspecialchars($nick) . "</b>$tag</li>";
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

    if( $user_id !== $_SESSION['user_id'] || $redis->hGet("chat:$chat_id:meta", 'admin') !== $_SESSION['user_id'] ) { error_log("Invalid Admin"); http_response_code(403); exit(json_encode(['error' => 'Invalid Admin'])); }

    $keysToDelete = [ "chat:$chat_id:meta", "chat:$chat_id:users", "chat:$chat_id:messages", ];
    $redis->unlink(...$keysToDelete); // delete all in background
    exit(json_encode([ 'success' => true ]));
}

function api_actions($redis, $chat_id, $user_id) {

    $data = json_decode(file_get_contents('php://input'), true);

    if (!is_array($data) || !isset($data['action']) ) { http_response_code(400); exit(json_encode(['error' => 'Invalid action'])); }

    // invite seen/rejected
    if( $data['action'] == 'invite' && isset( $data['invite'] ) && !empty( $data['invite'] ) ) {
        $key = "chat:$chat_id:invite:$user_id";
        $redis->sAdd($key, $data['invite']);
        $redis->expire($key, 2500000 ); // 30 days

    } else { error_log("Invalid action"); http_response_code(400); exit(json_encode( ['error' => 'Invalid action'] )); }

    echo json_encode(['success' => true]);
}
