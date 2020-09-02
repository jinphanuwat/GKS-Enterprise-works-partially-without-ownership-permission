<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class company extends Model
{
   
        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
    
        
        protected $fillable = [
            'company_name', 'contact_name', 'email', 'phone', 'address', 'company_file',
        ];
    
        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
           //
        ];
    
        /**
         * The attributes that should be cast to native types.
         *
         * @var array
         */
        protected $casts = [
            //
        ];
    
        public function user()
        {
            return $this->belongsTo('App\User');
        }


}
