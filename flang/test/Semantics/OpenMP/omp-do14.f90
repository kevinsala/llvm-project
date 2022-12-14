! RUN: %python %S/../test_symbols.py %s %flang_fc1 -fopenmp
! OpenMP Version 4.5
! 2.7.1 Do Loop constructs.

!DEF: /omp_cycle MainProgram
program omp_cycle
  !$omp do  collapse(1)
  !DEF: /omp_cycle/OtherConstruct1/i (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
  do i=0,10
    cycle
    !DEF: /omp_cycle/j (Implicit) ObjectEntity INTEGER(4)
    do j=0,10
      !DEF: /omp_cycle/k (Implicit) ObjectEntity INTEGER(4)
      do k=0,10
        !REF: /omp_cycle/OtherConstruct1/i
        !REF: /omp_cycle/j
        !REF: /omp_cycle/k
        print *, i, j, k
      end do
    end do
  end do
  !$omp end do

  !$omp do  collapse(1)
  !DEF: /omp_cycle/OtherConstruct2/i (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
  do i=0,10
    !REF: /omp_cycle/j
    do j=0,10
      cycle
      !REF: /omp_cycle/k
      do k=0,10
        !REF: /omp_cycle/OtherConstruct2/i
        !REF: /omp_cycle/j
        !REF: /omp_cycle/k
        print *, i, j, k
      end do
    end do
  end do
  !$omp end do

  !$omp do  collapse(2)
  !DEF: /omp_cycle/OtherConstruct3/i (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
  do i=0,10
    !DEF: /omp_cycle/OtherConstruct3/j (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
    do j=0,10
      !REF: /omp_cycle/k
      do k=0,10
        cycle
        !REF: /omp_cycle/OtherConstruct3/i
        !REF: /omp_cycle/OtherConstruct3/j
        !REF: /omp_cycle/k
        print *, i, j, k
      end do
    end do
  end do
  !$omp end do

  !$omp do  collapse(3)
  !DEF: /omp_cycle/OtherConstruct4/i (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
  do i=0,10
    !DEF: /omp_cycle/OtherConstruct4/j (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
    do j=0,10
      !DEF: /omp_cycle/OtherConstruct4/k (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
      do k=0,10
        cycle
        !REF: /omp_cycle/OtherConstruct4/i
        !REF: /omp_cycle/OtherConstruct4/j
        !REF: /omp_cycle/OtherConstruct4/k
        print *, i, j, k
      end do
    end do
  end do
  !$omp end do

  !$omp do  ordered(3)
  !DEF: /omp_cycle/OtherConstruct5/i (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
  foo:do i=0,10
    !DEF: /omp_cycle/OtherConstruct5/j (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
    foo1:do j=0,10
      !DEF: /omp_cycle/OtherConstruct5/k (OmpPrivate, OmpPreDetermined) HostAssoc INTEGER(4)
      foo2:do k=0,10
        cycle foo2
        !REF: /omp_cycle/OtherConstruct5/i
        !REF: /omp_cycle/OtherConstruct5/j
        !REF: /omp_cycle/OtherConstruct5/k
        print *, i, j, k
      end do foo2
    end do foo1
  end do foo
  !$omp end do
end program omp_cycle
