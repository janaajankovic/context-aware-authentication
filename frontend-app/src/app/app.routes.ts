import { Routes } from '@angular/router';
import { Login } from './login/login';
import { MfaVerify } from './mfa-verify/mfa-verify';
import { Dashboard } from './dashboard/dashboard';

export const routes: Routes = [
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', component: Login },
  { path: 'verify-mfa', component: MfaVerify },
  { path: 'dashboard', component: Dashboard }
];
