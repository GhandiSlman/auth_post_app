<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserAuthController extends Controller
{
    public function register(Request $request): \Illuminate\Http\JsonResponse
    {
        //the rules of validation are in RegisrationRequest so here we just call the method validated()
        $newUser=$request->validate([
            'email' => 'required|unique:users|email|max:255',
            'name' => 'required|string|max:255',
            'password' => 'required|min:6|confirmed',
            ]);
        //taking the password from the FRONT END and then hash it for security
        $newUser['password']=Hash::make($newUser['password']);
        $newUser['role']=2;


        $user=User::create($newUser);
        //creating a token for the newUser and send it with the name in the response
        $success['token']=$user->createToken('user',['app:all'])->plainTextToken;
        $success['name']=$user->name;
        $success['role']=$user->role;



        return response()->json([
            'status'=>true,
            'msg'=>'Registered successfully',
            'data'=>$success
        ],200);

    }

    public function login(Request $request){
        //validation
        $request->validate([
            'email'=>'required|email',
            'password'=>'required'
        ]);
        //check user
        $user=User::where("email","=",$request->email)->first();
        if(isset($user->id)){
            if(Hash::check($request->password,$user->password)){
                //create a token
                $token=$user->createToken('auth_token')->plainTextToken;
                $success['token']=$token;
                $success['role']=2;
                //send a response
                return response()->json([
                    'status'=>true,
                    'msg'=>"Logged in successfully",
                    'data'=>$success
                ],200);
            }else{
                return response()->json([
                    'status'=>false,
                    'msg'=>"Password does not match"
                ],404);
            }

        }else{
            return response()->json([
                'status'=>false,
                'msg'=>"user not found"
            ],404);
        }

    }

    public function profile(Request $request){

        return response()->json([
            'status'=>true,
            'msg'=>'User Profile Information',
            'data'=>auth()->user()

        ]);
    }

    public function logout(Request $request){
        auth()->user()->tokens()->delete();
        return response()->json([
            'status'=>true,
            'msg'=>'User Logged Out Successfully',
            'role'=>2,

        ]);
    }

}
