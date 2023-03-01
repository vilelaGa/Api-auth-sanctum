<?php

namespace App\Http\Controllers\Auth\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!auth()->attempt($credentials))
            abort(401, 'Invalid Credential');

        $token = auth()->user()->createToken('auth_token');

        return response()->json([
            'data' => [
                'token' => $token->plainTextToken
            ]
        ]);
    }

    public function logout()
    {
        // auth()->user()->tokens()->delete();
        auth()->user()->currentAccessToken()->delete();

        return response()->json(
            [
                'data' => [
                    'message' => 'Logout is success'
                ]
            ],
            201
        );
    }
}
