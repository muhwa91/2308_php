<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Exception;
use App\Exceptions\MyDBException;
use App\Http\Utils\TokenUtil;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;
use App\Models\Token;

class AuthController extends Controller
{
    protected $tokenDI;

    public function __construct(TokenUtil $tokenUtil) {
        $this->tokenDI = $tokenUtil;
    }
    // 에러 종류 : DB에러, system에러, 토큰에러, 정보획득에러
    /**
     * 로그인처리
     * 
     * @param Illuminate\Http\Request $request 리퀘스트 객체
     * @return string json 엑세스토큰, 쿠키httponly 리플레시토큰
     */
    public function login(Request $request) {

        // throw new MyDBException('E80');
        // DB 유저정보 획득
        $userInfo = User::where('u_id', $request->u_id)
        ->where('u_pw', $request->u_pw)
        ->first();
        Log::debug($userInfo);
        
        // 유저정보 NULL 확인
        if(is_null($userInfo)) {
            throw new Exception('E20');
        }

        // 토큰생성
        list($accessToken, $refreshToken) = $this->tokenDI->createTokens($userInfo);

        // 리플래시토큰 DB저장
        $this->tokenDI->upsertRefreshToken($refreshToken);

        // 리턴
        return response()->json([
            'access_token' => $accessToken
        ], 200)->cookie('refresh_token', $refreshToken, env('TOKEN_EXP_REFRESH'));
    }

    /**
     * 엑세스 토큰 재발급
     * @param Illuminate\Http\Request $request 리퀘스트 객체
     * @return string json 엑세스토큰, 쿠키httponly 리플레시토큰
     */
    public function reisstoken(Request $request) {
        // 리플래시토큰 획득
        $cookieRefreshToken = $request->cookie('refresh_token');

        // 리플래시토큰 확인
        $this->tokenDI->chkToken($cookieRefreshToken);

        // payload 내 u_pk 획득
        $u_pk = $this->tokenDI->getPayloadValueToKey($cookieRefreshToken, 'upk');

        // DB 유저정보 획득
        $userInfo = User::where('u_pk', $u_pk)->first();

        // 유저정보 획득 확인
        if(is_null($userInfo)) {
            throw new Exception('E20');
        }

        // DB 저장 리플래시토큰 검색
        $tokenInfo = Token::select('t_rt', 't_ext')
                        ->where('u_pk', $u_pk)
                        ->first();

        // 리플래시토큰 정보 획득 확인
        if(is_null($tokenInfo)) {
            throw new Exception('E04');
        }

        // 리플레시토큰 유효기간 체크
        if(strtotime($tokenInfo->t_ext) < time()) {
            throw new Exception('E02');
        }

        // 리플래시토큰 일치 확인
        if($cookieRefreshToken !== $tokenInfo->t_rt) {
            throw new Exception('E03');
        }

        // 토큰 재생성
        list($accessToken, $refreshToken) = $this->tokenDI->createTokens($userInfo);

        // 리플래시토큰 저장
        $this->tokenDI->upsertRefreshToken($refreshToken);

        // 리턴
        return response()->json([
            'access_token' => $accessToken
        ], 200)->cookie('refresh_token', $refreshToken, env('TOKEN_EXP_REFRESH'));
    }
}
