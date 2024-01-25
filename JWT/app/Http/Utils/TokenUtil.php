<?php
namespace App\Http\Utils;

use App\Models\User;
use App\Http\Utils\EncrypUtil;
use Exception;
use App\Exceptions\MyDBException;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use App\Models\Token;

class TokenUtil {

    /**
     * 토큰 생성
     * 
     * @param App\Models\User $userInfo 유저정보
     * @return list [$accessToken, $refreshToken]
     */
    
    public function createTokens(User $userInfo) {
        $accessToken = $this->createToken($userInfo, env('TOKEN_EXP_ACCESS'));
        $refreshToken = $this->createToken($userInfo, env('TOKEN_EXP_REFRESH'));

        return [$accessToken, $refreshToken];
    }

    /**
     * JWT 생성하여 리턴
     * 
     * @param App\Models\User $userInfo 유저정보
     * @param int $ttl 초 단위
     * @return string $header.'.'.$payload.'.'.$signature JWT
     */
    public function createToken(User $userInfo, int $ttl) {
        $header = $this->makeTokenHeader();
        $payload = $this->makeTokenPayload($userInfo, $ttl);
        $signature = $this->makeTokenSignature($header, $payload);
        return $header.'.'.$payload.'.'.$signature;
    }

    /**
     * 토큰 헤더 리턴
     * 
     * @return array 헤더 배열
     */
    protected function makeTokenHeader() {
        $arr = [
            'alg' => env('TOKEN_ALG'),
            'typ' => env('TOKEN_TYP'),
        ];
        return EncrypUtil::base64UrlEncode(json_encode($arr));
    }

    /**
     * 토큰 payload 리턴
     * 
     * @param App\Models\User $userInfo 유저정보
     * @param int $ttl 초 단위
     * @return array 헤더 배열
     */
    protected function makeTokenPayload(User $userInfo, int $ttl) {
        $now = time();
        $arr = [
            'upk' => $userInfo->u_pk,
            'name' => $userInfo->u_name,
            'iat' => $now,
            'ttl' => $ttl,
            'ext' => $now + $ttl
        ];
        return EncrypUtil::base64UrlEncode(json_encode($arr));
    }

    /**
     * 토큰의 시그니쳐 리턴
     * 
     * @param string $header base64UrlEncode된 header
     * @param string $payload base64UrlEncode된 payload
     * @return string signature
     */
    protected function makeTokenSignature(string $header, string $payload) {
        return EncrypUtil::hashWithSalt(env('TOKEN_ALG'), $header.'.'.$payload.env('TOKEN_SECRET_KEY'), env('TOKEN_SALT_LENGTH'));
    }

    /**
     * 토큰 분리
     * 
     * @param string $token 토큰
     * @return list header, payload, signature
     */
    public function explodeToken($token) {
        $arrToken = explode('.', $token);
        return [$arrToken[0], $arrToken[1], $arrToken[2]];
    }

    /**
     * 토큰에서 payload의 특정 키의 값 리턴
     * 
     * @param string $token 토큰
     * @param string $key payload key
     * @return string payload key 해당하는 값
     */
    public function getPayloadValueToKey(string $token, string $key) {
        list($header, $payload, $signature) = $this->explodeToken($token);
        $payloadDecoded = json_decode(EncrypUtil::base64UrlDecode($payload));

        if(is_null($payloadDecoded) || !isset($payloadDecoded->$key)) {
            throw new Exception('E05');
        }

        return $payloadDecoded->$key;
    }

    /**
     * 토큰 체크
     * 
     * @param string|null $token 베어럴 토큰
     * @return boolean true
     */
    public function chkToken(string|null $token) {
        // 토큰 존재 유무
        if(empty($token)) {
            throw new Exception('E01');
        }

        list($header, $payload, $signature) = $this->explodeToken($token);
        // 시그니쳐 동일여부 확인
        if(EncrypUtil::subStrSalt($signature, env('TOKEN_SALT_LENGTH')) 
            !== EncrypUtil::subStrSalt($this->makeTokenSignature($header, $payload), env('TOKEN_SALT_LENGTH'))) {
            throw new Exception('E03');
        }

        // 유효시간 확인
        if($this->getPayloadValueToKey($token, 'ext') < time()) {
            throw new Exception('E02');
        }

        return true;
    }

    /**
     * 리플래시토큰 DB 저장
     * 
     * @param string $refreshToken 리플래시토큰
     * @return boolean true
     */

    public function upsertRefreshToken(string $refreshToken) {
        // 리플래시토큰 DB 저장
        $ext = Carbon::createFromTimestamp($this->getPayloadValueToKey($refreshToken, 'ext'));
        
        try {
            DB::beginTransaction();
            Token::updateOrInsert(
                ['u_pk' => $this->getPayloadValueToKey($refreshToken, 'upk')],
                [
                    't_rt' => $refreshToken,
                    't_ext' => $ext->format('Y-m-d H:i:s')                    
                ]
            );
            DB::commit();
        } catch (Exception $e) {
            DB::rollback();
            Log::error("리플래시 토큰 저장 에러".$e->getMessage());
            throw new MyDBException('E80');
        }
        return true;
    }
}