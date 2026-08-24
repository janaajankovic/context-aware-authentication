import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-mfa-verify',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './mfa-verify.html'
})
export class MfaVerify {
  mfaCode: number | null = null;
  errorMessage = '';

  constructor(private authService: AuthService, private router: Router) {}

  onVerify() {
    if (!this.mfaCode) return;
    
    this.authService.verifyMfa(this.mfaCode).subscribe({
      next: (response) => {
        if (response.jwt) {
          this.authService.saveToken(response.jwt);
          this.router.navigate(['/dashboard']);
        }
      },
      error: () => {
        this.errorMessage = 'Neispravan kod! Pokušaj ponovo.';
      }
    });
  }
}