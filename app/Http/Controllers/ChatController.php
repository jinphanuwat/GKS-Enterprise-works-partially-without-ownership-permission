<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ChatController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function chat(){
        return redirect('chat');
    }

    public function send(Request $request){

        return $request->all();
        $user = User::find(Auth::id());
        $this->saveToSession($request);
        event(new ChatEvent($request->message, $user));

    }


    public function fetchMessages()
    {
        return Message::with('user')->get();
    }

    /*public function send(Request $request){
        $user = Auth::user();
        $message = $user->messages()->create([
            'message' => $request->input('message')
        ]);
        return ['status' => 'Message Sent!'];
    }
    */

    public function saveToSession(Request $request) {
        session()->put('chat',$request->message);
    }
    
    public function getOldMessages() {
        return session('chat');
    }

    public function deleteSession(){
        session()->forget('chat');
    }
}
