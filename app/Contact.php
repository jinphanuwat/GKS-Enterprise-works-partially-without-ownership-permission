<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Contact extends Model

{
    public $primaryKey = 'id';
    protected $fillable = [
        'name',
        'total_score',
        'email'   
    ];

    public function user()
    {
        return $this->belongsTo('App\User');
    }

}
