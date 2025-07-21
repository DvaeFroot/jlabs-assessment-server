<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
    /**
     * Register user.
     */
    public function register(Request $request): JsonResponse
    {
        $request->validate([
            'name' => ['required', 'min:3', 'max:30', Rule::unique('users', 'name')],
            'email' => ['required', 'email', Rule::unique('users', 'email')],
            'password' => ['required', 'min:8', 'max:50'],
        ]);
        $userData = $request->only('name', 'email', 'password');

        $userData['password'] = bcrypt($userData['password']);
        $user = User::create($userData);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    /**
     * Login user.
     */
    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => 'required',
        ]);

        $credentials = $request->only('email', 'password');
        if (! Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        /** @var \App\Models\User $user */
        $user = Auth::user();
        $token = $user->createToken('access_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    /**
     * Logout user.
     */
    public function logout(Request $request): JsonResponse
    {
        /** @var \App\Models\User $user */
        // $user = $request->user();
        // $user->tokens()->each(function ($token) {
        //     $token->delete();
        // });

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Get user details
     */
    public function me(Request $request): JsonResponse
    {
        return response()->json($request->user());
    }
}
