import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './login.html'
})
export class Login {
  username = '';
  password = '';
  errorMessage = '';

  constructor(private authService: AuthService, private router: Router) {}

  onLogin() {
    this.authService.login(this.username, this.password).subscribe({
      next: (response) => {
        // Ako je rizik mali, sistem odmah vraća token
        if (response.jwt) {
          this.authService.saveToken(response.jwt);
          this.router.navigate(['/dashboard']);
        }
      },
      error: (err) => {
        // Ako je rizik veliki, Spring Boot vraća 403 Forbidden
        if (err.status === 403) {
          this.router.navigate(['/verify-mfa']);
        } else {
          this.errorMessage = 'Pogrešni podaci ili greška na serveru.';
        }
      }
    });
  }
}