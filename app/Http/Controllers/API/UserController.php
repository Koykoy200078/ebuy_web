<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function loginUser(Request $request): Response
    {
        $validator = Validator::make($request->only('email', 'password'), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return Response([
                'success' => false,
                'message' => 'Validation errors',
                'errors' => $validator->errors()
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();
            $token = $user->createToken('eBuy')->accessToken;

            return Response([
                'success' => true,
                'message' => 'Login successful',
                'access_token' => $token,
            ], Response::HTTP_OK);
        }

        return Response([
            'success' => false,
            'message' => 'Login failed',
            'errors' => 'These credentials do not match our records.'
        ], Response::HTTP_UNAUTHORIZED);
    }

    public function getUserDetails(): Response
    {
        if (Auth::guard('api')->check()) {
            $user = Auth::guard('api')->user();

            return Response([
                'success' => true,
                'user' => $user,
            ], Response::HTTP_OK);
        }

        return Response([
            'success' => false,
            'error' => 'Unauthorized',
        ], Response::HTTP_UNAUTHORIZED);
    }

    public function logoutUser(): Response
    {
        if (Auth::guard('api')->check()) {
            $accessToken = Auth::guard('api')->user()->token();
            DB::table('oauth_refresh_tokens')
                ->where('access_token_id', $accessToken->id)
                ->update([
                    'revoked' => true,
                ]);
            $accessToken->revoke();

            return Response([
                'success' => true,
                'message' => 'User logged out successfully',
            ], Response::HTTP_OK);
        }

        return Response([
            'success' => false,
            'error' => 'Unauthorized',
        ], Response::HTTP_UNAUTHORIZED);
    }
}
