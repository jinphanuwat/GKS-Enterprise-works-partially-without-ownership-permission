<?php

namespace App;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable implements MustVerifyEmail
{
    use Notifiable;
    const ADMIN_TYPE = 1;
    const DEFAULT_TYPE = 0;
    protected $table = 'users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */

    
    public function isAdmin()
    {
        return $this->type === self::ADMIN_TYPE;
    }
    
    protected $fillable = [
        'name', 'email', 'password', 'type', 'total_score',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    public function company()
    {
        return $this->hasOne('App\company');
    }

    public function contact()
    {
        return $this->hasMany('App\company');
    }


}
