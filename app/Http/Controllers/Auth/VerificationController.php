<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\VerifiesEmails;

class VerificationController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Email Verification Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling email verification for any
    | user that recently registered with the application. Emails may also
    | be re-sent if the user didn't receive the original email message.
    |
    */

    use VerifiesEmails;

    /**
     * Where to redirect users after verification.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;


    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('signed')->only('verify');
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }

    public function resend(Request $request){    
        if($request->user()->hasVerfiedEmail()){
            return response(['message' => 'Already Verified']);
        }
        $request->user()->sendEmailVerificationNotification();
        if($request->wantsJson()){
            return response(['message' => 'Email Sent']);
        }
        return back()->with('resent', true);
    }

    public function verify(Request $request){
        auth()->loginUsingId($request->route('id'));
        if($request->route('id') != $request->user()->getKey()){
            throw new AuthorizationException;
        }
        elseif($request->user->hasVerfiiedEmail()) {
            return response(['message' => 'Already Verified']);
        }
        else {
            event(new Verified($request->user()));
        }
        return response(['message'=>'succesfully verified']);
    }
}