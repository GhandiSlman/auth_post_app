<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class ServiceOwner extends Model
{
    use HasApiTokens, HasFactory, Notifiable;
    protected $id='id';
    protected $table='service_owners';
    protected $fillable = [
        'name',
        'email',
        'password',
        'role'
    ];

}
