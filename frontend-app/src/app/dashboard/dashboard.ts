import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { CommonModule } from '@angular/common'; 

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule], 
  templateUrl: './dashboard.html'
})
export class Dashboard implements OnInit {
  
  dashboardData: any = null;

  constructor(private router: Router, private http: HttpClient) {}

  ngOnInit() {
    const token = localStorage.getItem('jwt_token');
    
    if (!token) {
      this.router.navigate(['/login']);
      return;
    }

    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });

    this.http.get('http://localhost:8080/api/dashboard/info', { headers }).subscribe({
      next: (data) => {
        this.dashboardData = data;
      },
      error: (err) => {
        console.error('Грешка приликом добављања података за дашборд:', err);
      }
    });
  }

  logout() {
    localStorage.removeItem('jwt_token');
    this.router.navigate(['/login']);
  }

  getBadgeClass(status: string): string {
    if (!status) return 'bg-soft-info';
    
    if (status === 'SUCCESS_LOW_RISK' || status === 'SUCCESS_MFA_VERIFIED') {
      return 'bg-soft-success';
    } else if (status === 'MFA_REQUIRED') {
      return 'bg-soft-warning';
    } else if (status.includes('FAILED') || status.includes('BLOCKED')) {
      return 'bg-soft-danger';
    }
    return 'bg-soft-info';
  }
}