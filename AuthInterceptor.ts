import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpResponse,
  HttpEventType
} from '@angular/common/http';
import {
  BehaviorSubject,
  filter,
  finalize,
  map,
  Observable,
  of,
  switchMap,
  take
} from 'rxjs';
import { catchError, throwError } from 'rxjs';
import { ToastService } from '../services/toast.service';
import { MasterDataService } from '../services/master-data.service';
import { LoaderService } from 'src/app/shared/services/loader/loader.service';
import { AuthenticationService } from '../services/authentication/authentication.service';
import { environment } from 'src/environments/environment';
import { EncryptionService } from '../services/encryption.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private totalRequests = 0;
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(
    null
  );

  constructor(
    private toastService: ToastService,
    private masterDataService: MasterDataService,
    private loader: LoaderService,
    private authenticationService: AuthenticationService,
    private encryptionService: EncryptionService
  ) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    this.loader.show();
    this.totalRequests++;

    return next.handle(this.addAuthHeader(req)).pipe(
      filter((response) => response instanceof HttpResponse),
      map((response) => {
        if (
          response instanceof HttpResponse &&
          response.body &&
          response.body.data
        ) {
          const data = response.body.data;

          const decryptedData = this.encryptionService.decrypt(data);

          const modifiedResponse = response.clone({
            body: JSON.parse(decryptedData)
          });

          return modifiedResponse;
        }
        return response;
      }),
      catchError((error) => {
        if (error.status === 401) {
          return this.handle401Error(req, next);
        } else {
          this.toastService.showError(error.error);
        }
        return throwError(() => error);
      }),

      finalize(() => {
        this.totalRequests--;
        if (this.totalRequests === 0) {
          this.loader.hide();
        }
      })
    );
  }
  private addAuthHeader(req: HttpRequest<any>): HttpRequest<any> {
    const masterData = this.masterDataService.getMasterData();
    const accessToken = this.masterDataService.getAccessToken();
    const userId = masterData?.userId ?? 0;
    const companyId = Number(localStorage.getItem('selectedCompany'))
      ? Number(localStorage.getItem('selectedCompany'))
      : masterData?.companyId
        ? masterData?.companyId
        : 1;
    const apiKey = environment.apiKey;

    return req.clone({
      headers: req.headers
        .set('Authorization', `Bearer ${accessToken}`)
        .set('UserId', userId.toString())
        .set('CompanyId', companyId.toString())
        .set('ApiKey', apiKey)
    });
  }

  private handle401Error(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return this.authenticationService.refreshToken().pipe(
        switchMap((newToken: string) => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(newToken);

          return next.handle(this.addAuthHeader(req));
        }),
        catchError((error) => {
          this.isRefreshing = false;
          return of(error);
        })
      );
    }
    return this.refreshTokenSubject.pipe(
      filter((token) => token != null),
      take(1),
      switchMap(() => next.handle(this.addAuthHeader(req)))
    );
  }
}
