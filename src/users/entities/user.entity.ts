import { Assignment } from "src/assignment/entities/assignment.entity";
import { Course } from "src/course/entities/course.entity";
import { Enrollment } from "src/enrollment/entities/enrollment.entity";
import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";

export type UserRole = 'student' | 'teacher' | 'admin';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    name: string;

    @Column()
    username: string;

    @Column({ unique: true })
    email: string

    @Column()
    password: string

    @Column({ type: 'varchar', default: 'student' })
    role: UserRole;

    @OneToMany(() => Enrollment, (enrollment) => enrollment.user)
    enrollments: Enrollment[];

    @OneToMany(() => Course, (course) => course.teacher)
    courses: Course[];

    @OneToMany(()=>Assignment,(assignment)=>assignment.student)
    assignment:Assignment[]
}
