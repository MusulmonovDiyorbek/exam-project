import { Enrollment } from "src/enrollment/entities/enrollment.entity";
import { Model } from "src/model/entities/model.entity";
import { User } from "src/users/entities/user.entity";
import { Column, Entity, ManyToOne, OneToMany, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Course {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    name: string;

    @Column()
    description: string;

    @Column()
    price: number;

    @Column()
    category: string;

    @Column()
    level: string;

    @ManyToOne(() => User, (user) => user.courses)
    teacher: User;

    @OneToMany(()=>Model,(model)=>model.course)
    model: Model[];

    @OneToMany(() =>Enrollment,(enroll)=> enroll.course)
    enrollments: Enrollment[];
}
