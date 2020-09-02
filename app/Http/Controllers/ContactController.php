<?php

namespace App\Http\Controllers;

use App\Contact;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class ContactController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $contacts = Contact::paginate(10);
        $contacts = Contact::orderBy('total_score', 'desc')->paginate(10)->setPath('contacts');

        return view('contacts.index', compact('contacts'));
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        return view('contacts.create');
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $request->validate([
            'name'=>'required',
            'total_score'=>'required',
            'email'=>'required'
        ]);
        if($request->input('contact'))
        {
            Contact::create($request->all());
            $contact = new Contact;
            $contact->name = $request->input('contact_name');
            $contact->email = $request->input('email');
            $contact->total_score = $request->input('total_score');
            Auth::user()->$contact->save();
        }

        return redirect()->back()->with('success', 'Created successfully.');
    }

    /**
     * 
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $contact = Contact::find($id);
        return view('contacts.show', compact(['contact']));
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        $contact = Contact::find($id);
        return view('contacts.edit', compact('contact')); 
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $request->validate([
            'name'=>'required',
            'total_score'=>'required',
            'email'=>'required|email'
        ]);
        
        //Contact::where('id', $id)->update($request->all());
        if($request->input('contact')){

            $contact = Contact::find($id);
            $contact->name =  $request->input('name');
            $contact->email = $request->input('email');
            $contact->total_score = $request->input('total_score');
            $contacts->save();

        }
      

        return redirect()->back()->with('success', 'Contact updated!');
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        
        Contact::where('id', $id)->delte();
        //$contact = Contact::findOrFail($id);
        //Auth::user()->$contact->delete();

        return redirect()->back()->with('success', 'Contact deleted!');
    }
}
