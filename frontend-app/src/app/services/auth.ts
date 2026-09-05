import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl = 'http://localhost:8080/api/auth';

  private tempUsername = '';

  constructor(private http: HttpClient) { }

  login(username: string, password: string): Observable<any> {
    this.tempUsername = username;
    return this.http.post(`${this.baseUrl}/login`, { username, password });
  }

  verifyMfa(mfaCode: number): Observable<any> {
    const preAuthToken = localStorage.getItem('preAuthToken');
    
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${preAuthToken}`
    });

    return this.http.post(`${this.baseUrl}/verify-mfa`, 
      { mfaCode: mfaCode }, 
      { headers: headers }
    );
  }

  saveToken(token: string) {
    localStorage.setItem('jwt_token', token);
  }
}