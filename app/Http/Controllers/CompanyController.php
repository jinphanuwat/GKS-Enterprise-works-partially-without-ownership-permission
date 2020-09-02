<?php

namespace App\Http\Controllers;


use App\Company;
use Illuminate\Http\Request;
use Intervention\Image\ImageManager;

class CompanyController extends Controller
{
    public function index() 
    {
        //return view ('/home');
        $companies = Company::all();
        return view('profile/{id}', compact('contacts'));

    }

    public function create()
    {
        //
    }


    
    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
                
    public function store(Request $request)
    {
    
        
            $request -> validate([
                'company_name'=>'required',
                'contact_name'=>'required',
                'email_new' => 'required|email',
                'phone' => 'required',
                'address' => 'required',
                'company_file' => 'required|image|mimes:jpeg,png,jpg,gif,svg|max:2048'
            ]);
            dd($request->all());
            $company = Company::create($request->all());
            $company = new Company();
            $email = $request->get('email');
            $company_name = $request->input('company_name');
            $contact_name = $request->input('contact_name');
            $email = $request->input('email_new');
            $phone = $request->input('phone');
            $address = $request->input('address');
            $company_file = $request->input('company_file');
            $company_filename = getFilename();
            $ImagePath = 'public/'+ $company_filename;
        /*$File = new File;

        if ($request->file('file')) {
          $FilePath = $request->file('file');
          $FileName = $FilePath->getClientOriginalName();

          $path = $request->file('file')->storeAs('uploads', $FileName, 'public');
        }

        $File->name = $FileName;
        $File->path = '/storage/'.$path;
        $File->save();

        return back()->with('success', 'File uploaded successfully');
        */
            $company->save();
            $manager = new ImageManager(array('driver' => 'imagick'));
            $image = $manager->make($ImagePath)->resize(300, 200);

        //return redirect('/home')->with('success', 'Record is successfully saved.');
    

    }
    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show()
    {
        $companies = Company::all();
        return view ('/user');
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
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
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }

}
