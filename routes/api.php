<?php

use App\Http\Controllers\Auth\ServiceOwnerAuthController;
use App\Http\Controllers\Auth\UserAuthController;
use App\Http\Controllers\CategoryController;
use App\Http\Controllers\OrderController;
use App\Models\ServiceOwner;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
//Registration for user and serviceOwner
Route::post('user/register', [UserAuthController::class, 'register']);
Route::post('serviceOwner/register', [ServiceOwnerAuthController::class, 'register']);

//Login for user and serviceOwner
Route::post('user/login', [UserAuthController::class, 'login']);
Route::post('serviceOwner/login', [ServiceOwnerAuthController::class, 'login']);

// Only for users
Route::middleware(['auth:user', 'type.user'])->group(function () {
    Route::get('/users/profile',[UserAuthController::class,'profile']);
    Route::get('/users/logout',[UserAuthController::class,'logout']);


});

// Only for service_owners
Route::middleware(['auth:serviceOwner', 'type.serviceOwner'])->group(function () {
   Route::get('/service_owners/profile',[ServiceOwnerAuthController::class,'profile']);
   Route::get('/service_owners/logout',[ServiceOwnerAuthController::class,'logout']);

});
