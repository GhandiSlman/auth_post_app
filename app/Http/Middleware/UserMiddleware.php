<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class UserMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {

            if (Auth::guard('user')->check()) {
                return $next($request);
            }

        return response()->json([
            'status'=>false,
            'msg'=>'Not Allowed to access!',
            'data'=>'Not Authorized'
        ],401);
    }
}
