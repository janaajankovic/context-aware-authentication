import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  // Putanja do tvog Spring Boot kontrolera
  private baseUrl = 'http://localhost:8080/api/auth';

  // Privremeno čuvamo username kako bismo ga prosledili MFA ekranu ako zatreba
  private tempUsername = '';

  constructor(private http: HttpClient) { }

  // 1. Zahtev za prijavu
  login(username: string, password: string): Observable<any> {
    this.tempUsername = username;
    return this.http.post(`${this.baseUrl}/login`, { username, password });
  }

  // 2. Zahtev za slanje MFA koda
  verifyMfa(mfaCode: number): Observable<any> {
    return this.http.post(`${this.baseUrl}/verify-mfa`, { 
      username: this.tempUsername, 
      mfaCode: mfaCode 
    });
  }

  // 3. Čuvanje JWT tokena u lokalnoj memoriji browsera
  saveToken(token: string) {
    localStorage.setItem('jwt_token', token);
  }
}