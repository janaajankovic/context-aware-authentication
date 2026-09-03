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
        if (err.status === 429) {
          this.errorMessage = 'Previše neuspješnih pokušaja. Pokušajte ponovo za 15 minuta.';
        } else if (err.status === 401) {
          this.errorMessage = 'Neispravno korisničko ime ili lozinka.';
        } else {
          this.errorMessage = 'Došlo je do greške pri komunikaciji sa serverom.';
        }
      }
    });
  }
}